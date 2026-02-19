// ============================================================================
// Domain 7: Intelligence Engine — Service Layer
// Tier 1 deterministic rules engine: condition evaluator & claim context builder
// ============================================================================

import type { Condition, CrossClaimQuery, SuggestionTemplate, SelectAiRule, SelectAiProviderLearning } from '@meritum/shared/schemas/db/intelligence.schema.js';
import { SuggestionPriority, SuggestionEventType, SuggestionCategory, SuggestionStatus, PRIORITY_THRESHOLD_DEFAULTS, SUPPRESSION_THRESHOLD, MIN_COHORT_SIZE, IntelAuditAction } from '@meritum/shared/constants/intelligence.constants.js';
import type { Tier2Deps } from './intel.llm.js';
import { analyseTier2 } from './intel.llm.js';

// ---------------------------------------------------------------------------
// Claim Context Types
// ---------------------------------------------------------------------------

/** Anonymised patient demographics for rule evaluation. NO PHN, NO name. */
export interface PatientDemographics {
  age: number;
  gender: string;
}

/** AHCIP-specific claim fields. */
export interface AhcipClaimFields {
  healthServiceCode: string;
  modifier1: string | null;
  modifier2: string | null;
  modifier3: string | null;
  diagnosticCode: string | null;
  functionalCentre: string;
  baNumber: string;
  encounterType: string;
  calls: number;
  timeSpent: number | null;
  facilityNumber: string | null;
  referralPractitioner: string | null;
  shadowBillingFlag: boolean;
  pcpcmBasketFlag: boolean;
  afterHoursFlag: boolean;
  afterHoursType: string | null;
  submittedFee: string | null;
}

/** WCB-specific claim fields (minimal for Tier 1 rules). */
export interface WcbClaimFields {
  formId: string;
  wcbClaimNumber: string | null;
}

/** Provider context for rule evaluation. */
export interface ProviderContext {
  specialtyCode: string;
  physicianType: string;
  defaultLocation: {
    functionalCentre: string;
    facilityNumber: string | null;
    rrnpEligible: boolean;
  } | null;
}

/** HSC code reference data resolved during context building. */
export interface HscCodeRef {
  hscCode: string;
  baseFee: string | null;
  feeType: string;
  specialtyRestrictions: string[];
  facilityRestrictions: string[];
  modifierEligibility: string[];
  pcpcmBasket: string;
  maxPerDay: number | null;
  requiresReferral: boolean;
  surchargeEligible: boolean;
}

/** Modifier reference data. */
export interface ModifierRef {
  modifierCode: string;
  type: string;
  calculationMethod: string;
  combinableWith: string[];
  exclusiveWith: string[];
  requiresTimeDocumentation: boolean;
}

/** DI code reference data. */
export interface DiCodeRef {
  diCode: string;
  qualifiesSurcharge: boolean;
  qualifiesBcp: boolean;
}

/** Reference data resolved during context building. */
export interface ReferenceDataContext {
  hscCode: HscCodeRef | null;
  modifiers: ModifierRef[];
  diagnosticCode: DiCodeRef | null;
  /** Dynamic reference sets resolved from ref.{key} lookups */
  sets: Record<string, string[]>;
}

/** Pre-fetched cross-claim data for aggregate conditions. */
export interface CrossClaimData {
  /** Key: serialised query descriptor. Value: aggregate result (number). */
  [queryKey: string]: number;
}

/** Complete pre-fetched claim context for rule evaluation. */
export interface ClaimContext {
  claim: {
    claimId: string;
    claimType: string;
    state: string;
    dateOfService: string;
    dayOfWeek: number;
    importSource: string;
  };
  ahcip: AhcipClaimFields | null;
  wcb: WcbClaimFields | null;
  patient: PatientDemographics;
  provider: ProviderContext;
  reference: ReferenceDataContext;
  crossClaim: CrossClaimData;
}

// ---------------------------------------------------------------------------
// Data-fetching dependencies (injected, not imported)
// ---------------------------------------------------------------------------

export interface ClaimData {
  claimId: string;
  claimType: string;
  state: string;
  dateOfService: string;
  importSource: string;
  patientId: string;
}

export interface AhcipData {
  healthServiceCode: string;
  modifier1: string | null;
  modifier2: string | null;
  modifier3: string | null;
  diagnosticCode: string | null;
  functionalCentre: string;
  baNumber: string;
  encounterType: string;
  calls: number;
  timeSpent: number | null;
  facilityNumber: string | null;
  referralPractitioner: string | null;
  shadowBillingFlag: boolean;
  pcpcmBasketFlag: boolean;
  afterHoursFlag: boolean;
  afterHoursType: string | null;
  submittedFee: string | null;
}

export interface WcbData {
  formId: string;
  wcbClaimNumber: string | null;
}

export interface PatientData {
  dateOfBirth: string;
  gender: string;
}

export interface ProviderData {
  specialtyCode: string;
  physicianType: string;
}

export interface LocationData {
  functionalCentre: string;
  facilityNumber: string | null;
  rrnpEligible: boolean;
}

export interface ClaimContextDeps {
  getClaim: (claimId: string, providerId: string) => Promise<ClaimData | null>;
  getAhcipDetails: (claimId: string) => Promise<AhcipData | null>;
  getWcbDetails: (claimId: string) => Promise<WcbData | null>;
  getPatientDemographics: (patientId: string, providerId: string) => Promise<PatientData | null>;
  getProvider: (providerId: string) => Promise<ProviderData | null>;
  getDefaultLocation: (providerId: string) => Promise<LocationData | null>;
  getHscCode: (hscCode: string) => Promise<HscCodeRef | null>;
  getModifierDefinitions: (modifierCodes: string[]) => Promise<ModifierRef[]>;
  getDiCode: (diCode: string) => Promise<DiCodeRef | null>;
  getReferenceSet: (setKey: string) => Promise<string[]>;
  getCrossClaimCount: (
    providerId: string,
    patientId: string,
    lookbackDays: number,
    field: string,
    filter?: Condition,
  ) => Promise<number>;
  getCrossClaimSum: (
    providerId: string,
    patientId: string,
    lookbackDays: number,
    field: string,
    filter?: Condition,
  ) => Promise<number>;
  getCrossClaimExists: (
    providerId: string,
    patientId: string,
    lookbackDays: number,
    field: string,
    filter?: Condition,
  ) => Promise<boolean>;
}

// ---------------------------------------------------------------------------
// Claim Context Builder
// ---------------------------------------------------------------------------

function calculateAge(dateOfBirth: string, dateOfService: string): number {
  const dob = new Date(dateOfBirth);
  const dos = new Date(dateOfService);
  let age = dos.getFullYear() - dob.getFullYear();
  const monthDiff = dos.getMonth() - dob.getMonth();
  if (monthDiff < 0 || (monthDiff === 0 && dos.getDate() < dob.getDate())) {
    age--;
  }
  return age;
}

function getDayOfWeek(dateStr: string): number {
  return new Date(dateStr).getDay();
}

/**
 * Build the pre-fetched claim context for Tier 1 rule evaluation.
 * All data is resolved here — the evaluator operates on this object only.
 * Patient PHN and name are NEVER included (anonymised to age + gender).
 */
export async function buildClaimContext(
  claimId: string,
  providerId: string,
  deps: ClaimContextDeps,
): Promise<ClaimContext | null> {
  const claim = await deps.getClaim(claimId, providerId);
  if (!claim) return null;

  // Fetch all data in parallel where possible
  const [ahcipData, wcbData, patientData, providerData, defaultLocation] = await Promise.all([
    claim.claimType === 'AHCIP' ? deps.getAhcipDetails(claimId) : Promise.resolve(null),
    claim.claimType === 'WCB' ? deps.getWcbDetails(claimId) : Promise.resolve(null),
    deps.getPatientDemographics(claim.patientId, providerId),
    deps.getProvider(providerId),
    deps.getDefaultLocation(providerId),
  ]);

  if (!patientData || !providerData) return null;

  // Resolve reference data based on claim type
  let hscCodeRef: HscCodeRef | null = null;
  let modifierRefs: ModifierRef[] = [];
  let diCodeRef: DiCodeRef | null = null;
  const referenceSets: Record<string, string[]> = {};

  if (ahcipData) {
    // Fetch HSC, modifiers, and DI code in parallel
    const modifierCodes = [
      ahcipData.modifier1,
      ahcipData.modifier2,
      ahcipData.modifier3,
    ].filter((m): m is string => m !== null);

    const [hsc, mods, di] = await Promise.all([
      deps.getHscCode(ahcipData.healthServiceCode),
      modifierCodes.length > 0
        ? deps.getModifierDefinitions(modifierCodes)
        : Promise.resolve([]),
      ahcipData.diagnosticCode
        ? deps.getDiCode(ahcipData.diagnosticCode)
        : Promise.resolve(null),
    ]);

    hscCodeRef = hsc;
    modifierRefs = mods;
    diCodeRef = di;
  }

  // Build anonymised patient demographics
  const patient: PatientDemographics = {
    age: calculateAge(patientData.dateOfBirth, claim.dateOfService),
    gender: patientData.gender,
  };

  // Build provider context
  const providerCtx: ProviderContext = {
    specialtyCode: providerData.specialtyCode,
    physicianType: providerData.physicianType,
    defaultLocation: defaultLocation
      ? {
          functionalCentre: defaultLocation.functionalCentre,
          facilityNumber: defaultLocation.facilityNumber,
          rrnpEligible: defaultLocation.rrnpEligible,
        }
      : null,
  };

  return {
    claim: {
      claimId: claim.claimId,
      claimType: claim.claimType,
      state: claim.state,
      dateOfService: claim.dateOfService,
      dayOfWeek: getDayOfWeek(claim.dateOfService),
      importSource: claim.importSource,
    },
    ahcip: ahcipData
      ? {
          healthServiceCode: ahcipData.healthServiceCode,
          modifier1: ahcipData.modifier1,
          modifier2: ahcipData.modifier2,
          modifier3: ahcipData.modifier3,
          diagnosticCode: ahcipData.diagnosticCode,
          functionalCentre: ahcipData.functionalCentre,
          baNumber: ahcipData.baNumber,
          encounterType: ahcipData.encounterType,
          calls: ahcipData.calls,
          timeSpent: ahcipData.timeSpent,
          facilityNumber: ahcipData.facilityNumber,
          referralPractitioner: ahcipData.referralPractitioner,
          shadowBillingFlag: ahcipData.shadowBillingFlag,
          pcpcmBasketFlag: ahcipData.pcpcmBasketFlag,
          afterHoursFlag: ahcipData.afterHoursFlag,
          afterHoursType: ahcipData.afterHoursType,
          submittedFee: ahcipData.submittedFee,
        }
      : null,
    wcb: wcbData
      ? {
          formId: wcbData.formId,
          wcbClaimNumber: wcbData.wcbClaimNumber,
        }
      : null,
    patient,
    provider: providerCtx,
    reference: {
      hscCode: hscCodeRef,
      modifiers: modifierRefs,
      diagnosticCode: diCodeRef,
      sets: referenceSets,
    },
    crossClaim: {},
  };
}

// ---------------------------------------------------------------------------
// Condition Evaluator
// ---------------------------------------------------------------------------

/**
 * Resolve a dot-notation field path against the claim context.
 * e.g., 'claim.dateOfService' → context.claim.dateOfService
 *       'ahcip.healthServiceCode' → context.ahcip.healthServiceCode
 *       'reference.hscCode.baseFee' → context.reference.hscCode.baseFee
 */
export function resolveField(context: ClaimContext, path: string): unknown {
  const parts = path.split('.');
  let current: unknown = context;

  for (const part of parts) {
    if (current === null || current === undefined) return undefined;
    if (typeof current !== 'object') return undefined;
    current = (current as Record<string, unknown>)[part];
  }

  return current;
}

/**
 * Resolve a value that may be a literal or a reference set lookup.
 * ref.{key} values are resolved from the pre-fetched reference sets in context.
 */
function resolveValue(
  value: unknown,
  context: ClaimContext,
): unknown {
  if (typeof value === 'string' && value.startsWith('ref.')) {
    const setKey = value.slice(4);
    return context.reference.sets[setKey] ?? [];
  }
  return value;
}

/**
 * Compare two values with the given operator.
 * Supports numeric comparison (falls back to string comparison for dates and non-numeric strings).
 */
function compareValues(left: unknown, operator: string, right: unknown): boolean {
  switch (operator) {
    case '==':
      return left === right || String(left) === String(right);
    case '!=':
      return left !== right && String(left) !== String(right);
    case '>':
    case '<':
    case '>=':
    case '<=': {
      // Try numeric comparison first
      const l = Number(left);
      const r = Number(right);
      if (!isNaN(l) && !isNaN(r)) {
        switch (operator) {
          case '>': return l > r;
          case '<': return l < r;
          case '>=': return l >= r;
          case '<=': return l <= r;
        }
      }
      // Fall back to string comparison (works for ISO date strings)
      const ls = String(left);
      const rs = String(right);
      switch (operator) {
        case '>': return ls > rs;
        case '<': return ls < rs;
        case '>=': return ls >= rs;
        case '<=': return ls <= rs;
      }
      return false;
    }
    default:
      return false;
  }
}

/**
 * Build a unique key for a cross-claim query to look up in pre-fetched data.
 */
export function crossClaimQueryKey(query: CrossClaimQuery): string {
  return `${query.aggregation}:${query.field}:${query.lookbackDays}:${JSON.stringify(query.filter ?? null)}`;
}

/**
 * Evaluate a condition tree against a pre-fetched claim context.
 *
 * SECURITY: This evaluator NEVER executes raw SQL. All data is pre-fetched
 * into the context object during the buildClaimContext phase. Cross-claim
 * queries are resolved to numeric aggregates before evaluation.
 *
 * @returns boolean — whether the condition is satisfied.
 */
export function evaluateCondition(
  condition: Condition,
  context: ClaimContext,
): boolean {
  switch (condition.type) {
    // --- Leaf: field comparison ---
    case 'field_compare': {
      if (!condition.field || condition.operator === undefined) return false;
      const fieldValue = resolveField(context, condition.field);
      const targetValue = resolveValue(condition.value, context);
      return compareValues(fieldValue, condition.operator, targetValue);
    }

    // --- Leaf: existence check ---
    case 'existence': {
      if (!condition.field || condition.operator === undefined) return false;
      const fieldValue = resolveField(context, condition.field);
      if (condition.operator === 'IS NULL') {
        return fieldValue === null || fieldValue === undefined;
      }
      if (condition.operator === 'IS NOT NULL') {
        return fieldValue !== null && fieldValue !== undefined;
      }
      return false;
    }

    // --- Leaf: set membership ---
    case 'set_membership': {
      if (!condition.field || condition.operator === undefined) return false;
      const fieldValue = resolveField(context, condition.field);
      const setValues = resolveValue(condition.value, context);

      if (!Array.isArray(setValues)) return false;

      const fieldStr = String(fieldValue);
      const isInSet = setValues.some((v) => String(v) === fieldStr);

      if (condition.operator === 'IN') return isInSet;
      if (condition.operator === 'NOT IN') return !isInSet;
      return false;
    }

    // --- Leaf: temporal ---
    case 'temporal': {
      if (!condition.field) return false;

      const fieldValue = resolveField(context, condition.field);

      // Weekday check: condition.value is an array of day numbers (0=Sun, 6=Sat)
      if (condition.operator === 'IN' && Array.isArray(condition.value)) {
        const dayNumber = typeof fieldValue === 'number'
          ? fieldValue
          : new Date(String(fieldValue)).getDay();
        return condition.value.includes(dayNumber);
      }

      // Time range check: condition.value is { start: string, end: string }
      if (
        condition.value &&
        typeof condition.value === 'object' &&
        !Array.isArray(condition.value) &&
        'start' in (condition.value as Record<string, unknown>) &&
        'end' in (condition.value as Record<string, unknown>)
      ) {
        const range = condition.value as { start: string; end: string };
        const timeStr = String(fieldValue);
        return timeStr >= range.start && timeStr <= range.end;
      }

      // Date/value comparison with operator (string comparison for ISO date strings)
      if (condition.operator && condition.value !== undefined) {
        const leftStr = String(fieldValue);
        const rightStr = String(condition.value);
        switch (condition.operator) {
          case '==': return leftStr === rightStr;
          case '!=': return leftStr !== rightStr;
          case '>': return leftStr > rightStr;
          case '<': return leftStr < rightStr;
          case '>=': return leftStr >= rightStr;
          case '<=': return leftStr <= rightStr;
          default: return false;
        }
      }

      return false;
    }

    // --- Leaf: cross-claim aggregate ---
    case 'cross_claim': {
      if (!condition.query) return false;
      const key = crossClaimQueryKey(condition.query);
      const aggregateValue = context.crossClaim[key];

      if (aggregateValue === undefined) return false;

      // Compare aggregate result with condition.value using condition.operator
      if (condition.operator && condition.value !== undefined) {
        return compareValues(aggregateValue, condition.operator, condition.value);
      }

      // For 'exists' aggregation without operator, treat as boolean
      if (condition.query.aggregation === 'exists') {
        return aggregateValue > 0;
      }

      return aggregateValue > 0;
    }

    // --- Combinator: AND (short-circuits on first false) ---
    case 'and': {
      if (!condition.children || condition.children.length === 0) return true;
      for (const child of condition.children) {
        if (!evaluateCondition(child, context)) return false;
      }
      return true;
    }

    // --- Combinator: OR (short-circuits on first true) ---
    case 'or': {
      if (!condition.children || condition.children.length === 0) return false;
      for (const child of condition.children) {
        if (evaluateCondition(child, context)) return true;
      }
      return false;
    }

    // --- Combinator: NOT ---
    case 'not': {
      if (!condition.children || condition.children.length === 0) return true;
      return !evaluateCondition(condition.children[0], context);
    }

    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// Pre-fetch cross-claim data into context
// ---------------------------------------------------------------------------

/**
 * Extract all cross_claim conditions from a condition tree.
 */
export function extractCrossClaimQueries(condition: Condition): CrossClaimQuery[] {
  const queries: CrossClaimQuery[] = [];

  if (condition.type === 'cross_claim' && condition.query) {
    queries.push(condition.query);
  }

  if (condition.children) {
    for (const child of condition.children) {
      queries.push(...extractCrossClaimQueries(child));
    }
  }

  return queries;
}

/**
 * Pre-fetch all cross-claim aggregates for a set of rules into the context.
 * This resolves all cross_claim conditions BEFORE evaluation, ensuring
 * the evaluator never executes database queries.
 */
export async function prefetchCrossClaimData(
  context: ClaimContext,
  conditions: Condition[],
  providerId: string,
  patientId: string,
  deps: ClaimContextDeps,
): Promise<void> {
  const queries: CrossClaimQuery[] = [];
  for (const cond of conditions) {
    queries.push(...extractCrossClaimQueries(cond));
  }

  // Deduplicate by query key
  const uniqueQueries = new Map<string, CrossClaimQuery>();
  for (const q of queries) {
    const key = crossClaimQueryKey(q);
    if (!uniqueQueries.has(key)) {
      uniqueQueries.set(key, q);
    }
  }

  // Fetch all in parallel
  const entries = Array.from(uniqueQueries.entries());
  const results = await Promise.all(
    entries.map(async ([key, query]) => {
      let value: number;
      switch (query.aggregation) {
        case 'count':
          value = await deps.getCrossClaimCount(
            providerId, patientId, query.lookbackDays, query.field, query.filter,
          );
          break;
        case 'sum':
          value = await deps.getCrossClaimSum(
            providerId, patientId, query.lookbackDays, query.field, query.filter,
          );
          break;
        case 'exists':
          value = (await deps.getCrossClaimExists(
            providerId, patientId, query.lookbackDays, query.field, query.filter,
          )) ? 1 : 0;
          break;
        default:
          value = 0;
      }
      return { key, value };
    }),
  );

  for (const { key, value } of results) {
    context.crossClaim[key] = value;
  }
}

// ---------------------------------------------------------------------------
// Tier 1 Types
// ---------------------------------------------------------------------------

/** A generated suggestion ready for the physician. */
export interface Suggestion {
  suggestionId: string;
  ruleId: string;
  tier: number;
  category: string;
  priority: SuggestionPriority;
  title: string;
  description: string;
  revenueImpact: number | null;
  confidence: number | null;
  sourceReference: string;
  sourceUrl: string | null;
  suggestedChanges: { field: string; valueFormula: string }[] | null;
  status?: string;
  resolvedAt?: string | null;
  resolvedBy?: string | null;
  dismissedReason?: string | null;
}

/** Dependencies for Tier 1 rule execution (repository calls). */
export interface Tier1Deps {
  getActiveRulesForClaim: (claimType: string, specialtyCode: string) => Promise<SelectAiRule[]>;
  getProviderLearningForRules: (providerId: string, ruleIds: string[]) => Promise<SelectAiProviderLearning[]>;
  incrementShown: (providerId: string, ruleId: string) => Promise<SelectAiProviderLearning>;
  appendSuggestionEvent: (event: {
    claimId: string;
    suggestionId: string;
    ruleId?: string | null;
    providerId: string;
    eventType: string;
    tier: number;
    category: string;
    revenueImpact?: string | null;
    dismissedReason?: string | null;
  }) => Promise<unknown>;
}

// ---------------------------------------------------------------------------
// Suggestion Template Rendering
// ---------------------------------------------------------------------------

/**
 * Interpolate {{placeholder}} tokens in a template string against the claim context.
 * Supported placeholders: any dot-path from ClaimContext (e.g., {{ahcip.healthServiceCode}}),
 * plus convenience aliases: {{hsc}}, {{modifier}}, {{fee_difference}}.
 */
function interpolate(template: string, context: ClaimContext): string {
  return template.replace(/\{\{(\w[\w.]*)\}\}/g, (_match, key: string) => {
    // Convenience aliases
    let resolved: unknown;
    switch (key) {
      case 'hsc':
        resolved = context.ahcip?.healthServiceCode ?? '';
        break;
      case 'modifier':
        resolved = context.ahcip?.modifier1 ?? '';
        break;
      case 'fee_difference':
        resolved = '0.00'; // Placeholder — calculated when revenue_impact_formula is evaluated
        break;
      default:
        resolved = resolveField(context, key);
        break;
    }
    return resolved !== null && resolved !== undefined ? String(resolved) : '';
  });
}

/**
 * Evaluate a priority formula string, applying provider priority adjustment.
 *
 * Formula types:
 * - `fixed:HIGH` / `fixed:MEDIUM` / `fixed:LOW` — fixed priority
 * - `revenue_based` — derived from revenue impact using threshold defaults
 *
 * Priority adjustment: -1 demotes (HIGH→MEDIUM, MEDIUM→LOW), +1 promotes (LOW→MEDIUM, MEDIUM→HIGH).
 * Priority can never be promoted above the rule-defined maximum.
 */
function evaluatePriority(
  formula: string,
  revenueImpact: number | null,
  priorityAdjustment: number,
): SuggestionPriority {
  const PRIORITY_ORDER: SuggestionPriority[] = [
    SuggestionPriority.LOW,
    SuggestionPriority.MEDIUM,
    SuggestionPriority.HIGH,
  ];

  let basePriority: SuggestionPriority;

  if (formula.startsWith('fixed:')) {
    const level = formula.slice(6) as SuggestionPriority;
    if (PRIORITY_ORDER.includes(level)) {
      basePriority = level;
    } else {
      basePriority = SuggestionPriority.LOW;
    }
  } else if (formula === 'revenue_based') {
    if (revenueImpact === null) {
      basePriority = SuggestionPriority.LOW;
    } else {
      const highMin = parseFloat(PRIORITY_THRESHOLD_DEFAULTS.HIGH.revenueImpactMin);
      const medMin = parseFloat(PRIORITY_THRESHOLD_DEFAULTS.MEDIUM.revenueImpactMin);
      if (revenueImpact >= highMin) {
        basePriority = SuggestionPriority.HIGH;
      } else if (revenueImpact >= medMin) {
        basePriority = SuggestionPriority.MEDIUM;
      } else {
        basePriority = SuggestionPriority.LOW;
      }
    }
  } else {
    basePriority = SuggestionPriority.MEDIUM;
  }

  // Apply priority adjustment (negative = demote, positive would promote but never above base max)
  const baseIndex = PRIORITY_ORDER.indexOf(basePriority);
  const maxIndex = baseIndex; // Cannot promote above rule-defined maximum
  const adjustedIndex = Math.max(0, Math.min(maxIndex, baseIndex + priorityAdjustment));
  return PRIORITY_ORDER[adjustedIndex];
}

/**
 * Evaluate a revenue impact formula against the claim context.
 * Supported formulas:
 * - `fixed:XX.XX` — literal numeric value
 * - `fee_lookup:{hsc_code}` — look up base fee from reference data
 * - `fee_difference:{field}` — difference between reference fee and submitted
 * - absent or empty → null
 */
function evaluateRevenueImpact(
  formula: string | undefined,
  context: ClaimContext,
): number | null {
  if (!formula) return null;

  if (formula.startsWith('fixed:')) {
    const val = parseFloat(formula.slice(6));
    return isNaN(val) ? null : val;
  }

  if (formula === 'fee_lookup' || formula.startsWith('fee_lookup:')) {
    const baseFee = context.reference.hscCode?.baseFee;
    return baseFee ? parseFloat(baseFee) : null;
  }

  if (formula === 'fee_difference') {
    const baseFee = context.reference.hscCode?.baseFee;
    const submitted = context.ahcip?.submittedFee;
    if (baseFee && submitted) {
      const diff = parseFloat(baseFee) - parseFloat(submitted);
      return Math.abs(diff);
    }
    return null;
  }

  // Default: try parsing as a number
  const val = parseFloat(formula);
  return isNaN(val) ? null : val;
}

/**
 * Render a suggestion from a rule's template, claim context, and provider's priority adjustment.
 * Returns a fully populated Suggestion object.
 */
export function renderSuggestion(
  rule: SelectAiRule,
  template: SuggestionTemplate,
  context: ClaimContext,
  priorityAdjustment: number,
): Suggestion {
  const revenueImpact = evaluateRevenueImpact(template.revenue_impact_formula, context);
  const priority = evaluatePriority(rule.priorityFormula, revenueImpact, priorityAdjustment);

  return {
    suggestionId: crypto.randomUUID(),
    ruleId: rule.ruleId,
    tier: 1,
    category: rule.category,
    priority,
    title: interpolate(template.title, context),
    description: interpolate(template.description, context),
    revenueImpact,
    confidence: 1.0,
    sourceReference: template.source_reference,
    sourceUrl: template.source_url ?? null,
    suggestedChanges: template.suggested_changes
      ? template.suggested_changes.map((c) => ({
          field: c.field,
          valueFormula: c.value_formula,
        }))
      : null,
  };
}

// ---------------------------------------------------------------------------
// Priority sort weight
// ---------------------------------------------------------------------------

const PRIORITY_WEIGHT: Record<string, number> = {
  [SuggestionPriority.HIGH]: 3,
  [SuggestionPriority.MEDIUM]: 2,
  [SuggestionPriority.LOW]: 1,
};

// ---------------------------------------------------------------------------
// Tier 1 Rule Execution
// ---------------------------------------------------------------------------

/**
 * Evaluate all Tier 1 rules against a claim and generate suggestions.
 *
 * 1. Build claim context.
 * 2. Determine claim_type and provider specialty.
 * 3. Fetch active rules for this claim_type and specialty.
 * 4. Batch-fetch learning states for provider + all candidate rules.
 * 5. For each rule: check suppression, evaluate condition, render suggestion,
 *    record GENERATED event, increment times_shown.
 * 6. Deduplicate same-field suggestions (keep highest priority).
 * 7. Sort by priority (HIGH first), then revenue_impact descending.
 *
 * @returns Suggestion[] — sorted and deduplicated.
 */
export async function evaluateTier1Rules(
  claimId: string,
  providerId: string,
  contextDeps: ClaimContextDeps,
  tier1Deps: Tier1Deps,
): Promise<Suggestion[]> {
  // 1. Build claim context
  const context = await buildClaimContext(claimId, providerId, contextDeps);
  if (!context) return [];

  const claimType = context.claim.claimType;
  const specialtyCode = context.provider.specialtyCode;

  // 3. Fetch active rules for this claim_type and specialty
  const rules = await tier1Deps.getActiveRulesForClaim(claimType, specialtyCode);
  if (rules.length === 0) return [];

  // 4. Batch-fetch learning states
  const ruleIds = rules.map((r) => r.ruleId);
  const learningStates = await tier1Deps.getProviderLearningForRules(providerId, ruleIds);
  const learningMap = new Map<string, SelectAiProviderLearning>();
  for (const ls of learningStates) {
    learningMap.set(ls.ruleId, ls);
  }

  // Pre-fetch cross-claim data for all rule conditions
  const allConditions = rules.map((r) => r.conditions as Condition);
  const patientClaim = await contextDeps.getClaim(claimId, providerId);
  if (patientClaim) {
    await prefetchCrossClaimData(
      context,
      allConditions,
      providerId,
      patientClaim.patientId,
      contextDeps,
    );
  }

  // 5. Evaluate each rule
  const suggestions: Suggestion[] = [];

  for (const rule of rules) {
    // 5a. Check suppression
    const learning = learningMap.get(rule.ruleId);
    if (learning?.isSuppressed) continue;

    // 5b. Evaluate condition tree
    const condition = rule.conditions as Condition;
    if (!evaluateCondition(condition, context)) continue;

    // 5c. Render suggestion
    const template = rule.suggestionTemplate as SuggestionTemplate;
    const priorityAdjustment = learning?.priorityAdjustment ?? 0;
    const suggestion = renderSuggestion(rule, template, context, priorityAdjustment);

    suggestions.push(suggestion);

    // 5e. Record GENERATED event (fire-and-forget for performance)
    tier1Deps.appendSuggestionEvent({
      claimId,
      suggestionId: suggestion.suggestionId,
      ruleId: rule.ruleId,
      providerId,
      eventType: SuggestionEventType.GENERATED,
      tier: 1,
      category: rule.category,
      revenueImpact: suggestion.revenueImpact !== null
        ? suggestion.revenueImpact.toFixed(2)
        : null,
    });

    // 5f. Increment times_shown (fire-and-forget)
    tier1Deps.incrementShown(providerId, rule.ruleId);
  }

  // 6. Deduplicate: if multiple suggestions target the same field, keep highest priority
  const deduped = deduplicateSuggestions(suggestions);

  // 7. Sort by priority (HIGH first), then revenue_impact descending
  deduped.sort((a, b) => {
    const pw = (PRIORITY_WEIGHT[b.priority] ?? 0) - (PRIORITY_WEIGHT[a.priority] ?? 0);
    if (pw !== 0) return pw;
    const aImpact = a.revenueImpact ?? 0;
    const bImpact = b.revenueImpact ?? 0;
    return bImpact - aImpact;
  });

  return deduped;
}

/**
 * Deduplicate suggestions that target the same field.
 * When multiple rules produce suggestions with the same suggestedChanges field,
 * keep the one with the highest priority (and highest revenue impact as tiebreaker).
 */
function deduplicateSuggestions(suggestions: Suggestion[]): Suggestion[] {
  // Group by target field (first suggested_changes field, or category+ruleId if none)
  const fieldMap = new Map<string, Suggestion>();
  const noField: Suggestion[] = [];

  for (const s of suggestions) {
    const targetField = s.suggestedChanges?.[0]?.field;
    if (!targetField) {
      noField.push(s);
      continue;
    }

    const existing = fieldMap.get(targetField);
    if (!existing) {
      fieldMap.set(targetField, s);
      continue;
    }

    // Keep highest priority, then highest revenue impact
    const existingWeight = PRIORITY_WEIGHT[existing.priority] ?? 0;
    const newWeight = PRIORITY_WEIGHT[s.priority] ?? 0;
    if (newWeight > existingWeight) {
      fieldMap.set(targetField, s);
    } else if (newWeight === existingWeight) {
      if ((s.revenueImpact ?? 0) > (existing.revenueImpact ?? 0)) {
        fieldMap.set(targetField, s);
      }
    }
  }

  return [...fieldMap.values(), ...noField];
}

// ---------------------------------------------------------------------------
// Tier 3 Review Flagging
// ---------------------------------------------------------------------------

/**
 * Generate a Tier 3 suggestion: review recommended.
 *
 * Tier 3 triggers: LLM confidence < 0.60, complex GR interactions,
 * novel code combinations, conflicting rules, complex SOMB change impact.
 *
 * Tier 3 suggestions have:
 * - tier = 3
 * - category = REVIEW_RECOMMENDED
 * - suggested_changes = null (no one-click accept)
 * - revenue_impact = null (cannot calculate for ambiguous)
 * - confidence = null (explicitly null — human review needed)
 */
export function generateTier3Suggestion(
  trigger: string,
  context: ClaimContext,
  sourceReference: string,
  sourceUrl?: string,
): Suggestion {
  const hsc = context.ahcip?.healthServiceCode ?? 'this claim';

  // Build trigger-specific titles and descriptions per FRD Section 5.3
  let title: string;
  let description: string;

  switch (trigger) {
    case 'llm_low_confidence':
      title = `Review recommended for ${hsc} — automated analysis inconclusive`;
      description = `The automated analysis could not reach a confident conclusion for ${hsc}. Please review the referenced source to determine if adjustments are needed.`;
      break;
    case 'complex_gr_interaction':
      title = `Complex governing rule interactions may affect ${hsc}`;
      description = `Multiple governing rules interact for ${hsc} in ways that depend on clinical context Meritum cannot verify. Please review the referenced rules.`;
      break;
    case 'novel_code_combination':
      title = `Unusual code/modifier combination on ${hsc}`;
      description = `The code/modifier combination on this claim has not been seen in your billing history or your specialty's typical patterns. Please verify it is correct.`;
      break;
    case 'conflicting_rules':
      title = `Conflicting rules detected for ${hsc}`;
      description = `Two or more governing rules produce contradictory guidance for ${hsc}. Manual review is needed to determine the correct billing approach.`;
      break;
    case 'somb_change_impact':
      title = `Recent SOMB changes may affect billing for ${hsc}`;
      description = `A recent SOMB update affects ${hsc}, which you bill frequently. The change is complex enough to warrant manual review before continuing.`;
      break;
    default:
      title = `Review recommended for ${hsc}`;
      description = `This claim requires manual review. Please consult the referenced source for guidance.`;
      break;
  }

  return {
    suggestionId: crypto.randomUUID(),
    ruleId: '',
    tier: 3,
    category: SuggestionCategory.REVIEW_RECOMMENDED,
    priority: SuggestionPriority.MEDIUM,
    title,
    description,
    revenueImpact: null,
    confidence: null,
    sourceReference,
    sourceUrl: sourceUrl ?? null,
    suggestedChanges: null,
    status: SuggestionStatus.PENDING,
  };
}

// ---------------------------------------------------------------------------
// Suggestion Lifecycle Dependencies
// ---------------------------------------------------------------------------

export interface LifecycleDeps {
  /** Get a claim's ai_coach_suggestions JSONB */
  getClaimSuggestions: (claimId: string, providerId: string) => Promise<Suggestion[] | null>;
  /** Update a claim's ai_coach_suggestions JSONB */
  updateClaimSuggestions: (claimId: string, providerId: string, suggestions: Suggestion[]) => Promise<void>;
  /** Apply suggested changes to the claim (call Domain 4 update) */
  applyClaimChanges: (claimId: string, providerId: string, changes: { field: string; valueFormula: string }[]) => Promise<void>;
  /** Trigger claim revalidation (Domain 4.0) */
  revalidateClaim: (claimId: string, providerId: string) => Promise<void>;
  /** Append a suggestion event to the audit log */
  appendSuggestionEvent: (event: {
    claimId: string;
    suggestionId: string;
    ruleId?: string | null;
    providerId: string;
    eventType: string;
    tier: number;
    category: string;
    revenueImpact?: string | null;
    dismissedReason?: string | null;
  }) => Promise<unknown>;
  /** Record acceptance in learning state */
  recordAcceptance: (providerId: string, ruleId: string) => Promise<SelectAiProviderLearning>;
  /** Record dismissal in learning state */
  recordDismissal: (providerId: string, ruleId: string) => Promise<SelectAiProviderLearning>;
}

// ---------------------------------------------------------------------------
// Suggestion Lifecycle: Accept
// ---------------------------------------------------------------------------

/**
 * Accept a suggestion:
 * 1. Find suggestion in claim's ai_coach_suggestions JSONB.
 * 2. Apply suggested_changes to the claim (call Domain 4 update).
 * 3. Set suggestion status = ACCEPTED, resolved_at, resolved_by.
 * 4. Record ACCEPTED event in ai_suggestion_events.
 * 5. Update learning state: recordAcceptance (resets consecutive_dismissals).
 * 6. Trigger claim revalidation (Domain 4.0).
 */
export async function acceptSuggestion(
  claimId: string,
  suggestionId: string,
  providerId: string,
  lifecycleDeps: LifecycleDeps,
): Promise<Suggestion | null> {
  const suggestions = await lifecycleDeps.getClaimSuggestions(claimId, providerId);
  if (!suggestions) return null;

  const index = suggestions.findIndex((s) => s.suggestionId === suggestionId);
  if (index === -1) return null;

  const suggestion = suggestions[index];

  // 2. Apply suggested_changes to the claim
  if (suggestion.suggestedChanges && suggestion.suggestedChanges.length > 0) {
    await lifecycleDeps.applyClaimChanges(claimId, providerId, suggestion.suggestedChanges);
  }

  // 3. Update suggestion status
  const now = new Date().toISOString();
  suggestion.status = SuggestionStatus.ACCEPTED;
  suggestion.resolvedAt = now;
  suggestion.resolvedBy = providerId;

  suggestions[index] = suggestion;
  await lifecycleDeps.updateClaimSuggestions(claimId, providerId, suggestions);

  // 4. Record ACCEPTED event
  await lifecycleDeps.appendSuggestionEvent({
    claimId,
    suggestionId,
    ruleId: suggestion.ruleId || null,
    providerId,
    eventType: SuggestionEventType.ACCEPTED,
    tier: suggestion.tier,
    category: suggestion.category,
    revenueImpact: suggestion.revenueImpact !== null
      ? suggestion.revenueImpact.toFixed(2)
      : null,
  });

  // 5. Update learning state (reset consecutive dismissals)
  if (suggestion.ruleId) {
    await lifecycleDeps.recordAcceptance(providerId, suggestion.ruleId);
  }

  // 6. Trigger claim revalidation
  await lifecycleDeps.revalidateClaim(claimId, providerId);

  return suggestion;
}

// ---------------------------------------------------------------------------
// Suggestion Lifecycle: Dismiss
// ---------------------------------------------------------------------------

/**
 * Dismiss a suggestion:
 * 1. Set suggestion status = DISMISSED, dismissed_reason, resolved_at, resolved_by.
 * 2. Record DISMISSED event with reason.
 * 3. Update learning state: recordDismissal (increment consecutive, check suppression threshold).
 */
export async function dismissSuggestion(
  claimId: string,
  suggestionId: string,
  providerId: string,
  lifecycleDeps: LifecycleDeps,
  reason?: string,
): Promise<Suggestion | null> {
  const suggestions = await lifecycleDeps.getClaimSuggestions(claimId, providerId);
  if (!suggestions) return null;

  const index = suggestions.findIndex((s) => s.suggestionId === suggestionId);
  if (index === -1) return null;

  const suggestion = suggestions[index];

  // 1. Update suggestion status
  const now = new Date().toISOString();
  suggestion.status = SuggestionStatus.DISMISSED;
  suggestion.dismissedReason = reason ?? null;
  suggestion.resolvedAt = now;
  suggestion.resolvedBy = providerId;

  suggestions[index] = suggestion;
  await lifecycleDeps.updateClaimSuggestions(claimId, providerId, suggestions);

  // 2. Record DISMISSED event
  await lifecycleDeps.appendSuggestionEvent({
    claimId,
    suggestionId,
    ruleId: suggestion.ruleId || null,
    providerId,
    eventType: SuggestionEventType.DISMISSED,
    tier: suggestion.tier,
    category: suggestion.category,
    revenueImpact: suggestion.revenueImpact !== null
      ? suggestion.revenueImpact.toFixed(2)
      : null,
    dismissedReason: reason ?? null,
  });

  // 3. Update learning state (increment consecutive dismissals, check suppression)
  if (suggestion.ruleId) {
    await lifecycleDeps.recordDismissal(providerId, suggestion.ruleId);
  }

  return suggestion;
}

// ---------------------------------------------------------------------------
// Suggestion Lifecycle: Read
// ---------------------------------------------------------------------------

/**
 * Get all suggestions for a claim. Fast read from JSONB, no analysis.
 */
export async function getClaimSuggestions(
  claimId: string,
  providerId: string,
  lifecycleDeps: Pick<LifecycleDeps, 'getClaimSuggestions'>,
): Promise<Suggestion[]> {
  const suggestions = await lifecycleDeps.getClaimSuggestions(claimId, providerId);
  return suggestions ?? [];
}

// ---------------------------------------------------------------------------
// Analysis Orchestrator Dependencies
// ---------------------------------------------------------------------------

export interface AnalyseDeps {
  contextDeps: ClaimContextDeps;
  tier1Deps: Tier1Deps;
  tier2Deps: Tier2Deps;
  lifecycleDeps: LifecycleDeps;
  /** Audit log callback for intelligence.claim_analysed events */
  auditLog: (entry: {
    action: string;
    claimId: string;
    providerId: string;
    details: Record<string, unknown>;
  }) => Promise<void>;
  /** Notify via WebSocket channel intelligence:claim:{claimId} */
  notifyWs?: (claimId: string, event: string, payload: unknown) => void;
}

// ---------------------------------------------------------------------------
// Analysis Orchestrator: analyseClaim
// ---------------------------------------------------------------------------

/**
 * Full analysis pipeline for a claim:
 *
 * 1. Tier 1 (synchronous): evaluate deterministic rules → Suggestion[].
 * 2. Store Tier 1 results on claim's ai_coach_suggestions JSONB.
 * 3. Return Tier 1 results to caller immediately.
 * 4. Tier 2 (async fire-and-forget): LLM analysis in background.
 *    On completion: append Tier 2 suggestions to claim's JSONB.
 *    Notify via WebSocket channel intelligence:claim:{claimId}.
 *    On timeout or failure: no degradation — Tier 1 already delivered.
 * 5. Tier 3 flags from Tier 1 or low-confidence Tier 2 are included.
 */
export async function analyseClaim(
  claimId: string,
  providerId: string,
  deps: AnalyseDeps,
): Promise<Suggestion[]> {
  // 1. Tier 1 synchronous evaluation
  const tier1Suggestions = await evaluateTier1Rules(
    claimId,
    providerId,
    deps.contextDeps,
    deps.tier1Deps,
  );

  // Mark all Tier 1 suggestions as PENDING
  for (const s of tier1Suggestions) {
    s.status = SuggestionStatus.PENDING;
  }

  // 2. Store Tier 1 results on claim's ai_coach_suggestions JSONB
  await deps.lifecycleDeps.updateClaimSuggestions(claimId, providerId, tier1Suggestions);

  // Count tier 3 flags from Tier 1 results
  const tier3Count = tier1Suggestions.filter((s) => s.tier === 3).length;

  // 3. Audit log the analysis
  deps.auditLog({
    action: IntelAuditAction.CLAIM_ANALYSED,
    claimId,
    providerId,
    details: {
      tier1Count: tier1Suggestions.length,
      tier2Triggered: !!deps.tier2Deps.llmClient,
      tier3Count,
    },
  }).catch(() => {/* fire-and-forget audit */});

  // 4. Tier 2 async fire-and-forget
  if (deps.tier2Deps.llmClient) {
    // Build claim context for Tier 2 (reuse context deps)
    const context = await buildClaimContext(claimId, providerId, deps.contextDeps);

    if (context) {
      // Fire-and-forget: do not await
      runTier2InBackground(claimId, providerId, context, tier1Suggestions, deps)
        .catch(() => {/* Tier 2 failure is non-fatal */});
    }
  }

  // 5. Return Tier 1 results immediately
  return tier1Suggestions;
}

/**
 * Run Tier 2 analysis in the background.
 * On completion: append Tier 2 suggestions to claim JSONB and notify via WS.
 */
async function runTier2InBackground(
  claimId: string,
  providerId: string,
  context: ClaimContext,
  tier1Results: Suggestion[],
  deps: AnalyseDeps,
): Promise<void> {
  const tier2Suggestions = await analyseTier2(
    claimId,
    providerId,
    context,
    tier1Results,
    deps.tier2Deps,
  );

  if (tier2Suggestions.length === 0) return;

  // Mark as PENDING
  for (const s of tier2Suggestions) {
    s.status = SuggestionStatus.PENDING;
  }

  // Append Tier 2 suggestions to existing claim JSONB
  const existing = await deps.lifecycleDeps.getClaimSuggestions(claimId, providerId) ?? [];
  const merged = [...existing, ...tier2Suggestions];
  await deps.lifecycleDeps.updateClaimSuggestions(claimId, providerId, merged);

  // Notify via WebSocket
  if (deps.notifyWs) {
    deps.notifyWs(claimId, 'tier2_complete', {
      suggestions: tier2Suggestions,
    });
  }
}

// ---------------------------------------------------------------------------
// Analysis Orchestrator: reanalyseClaim
// ---------------------------------------------------------------------------

/**
 * Re-run analysis after a claim update:
 * 1. Clear previous PENDING suggestions (preserve ACCEPTED/DISMISSED).
 * 2. Run full analysis pipeline.
 * 3. Merge new suggestions with preserved ones.
 */
export async function reanalyseClaim(
  claimId: string,
  providerId: string,
  deps: AnalyseDeps,
): Promise<Suggestion[]> {
  // 1. Get existing suggestions, partition by status
  const existing = await deps.lifecycleDeps.getClaimSuggestions(claimId, providerId) ?? [];
  const preserved = existing.filter(
    (s) => s.status === SuggestionStatus.ACCEPTED || s.status === SuggestionStatus.DISMISSED,
  );

  // Clear PENDING suggestions by writing only preserved ones
  await deps.lifecycleDeps.updateClaimSuggestions(claimId, providerId, preserved);

  // 2. Run Tier 1 evaluation
  const tier1Suggestions = await evaluateTier1Rules(
    claimId,
    providerId,
    deps.contextDeps,
    deps.tier1Deps,
  );

  for (const s of tier1Suggestions) {
    s.status = SuggestionStatus.PENDING;
  }

  // 3. Merge with preserved and store
  const merged = [...preserved, ...tier1Suggestions];
  await deps.lifecycleDeps.updateClaimSuggestions(claimId, providerId, merged);

  const tier3Count = tier1Suggestions.filter((s) => s.tier === 3).length;

  // Audit log the reanalysis
  deps.auditLog({
    action: IntelAuditAction.CLAIM_ANALYSED,
    claimId,
    providerId,
    details: {
      tier1Count: tier1Suggestions.length,
      tier2Triggered: !!deps.tier2Deps.llmClient,
      tier3Count,
      isReanalysis: true,
      preservedCount: preserved.length,
    },
  }).catch(() => {/* fire-and-forget audit */});

  // 4. Tier 2 async fire-and-forget
  if (deps.tier2Deps.llmClient) {
    const context = await buildClaimContext(claimId, providerId, deps.contextDeps);

    if (context) {
      runTier2InBackground(claimId, providerId, context, tier1Suggestions, deps)
        .catch(() => {/* Tier 2 failure is non-fatal */});
    }
  }

  // 5. Return new Tier 1 results
  return tier1Suggestions;
}

// ---------------------------------------------------------------------------
// Learning Loop Dependencies
// ---------------------------------------------------------------------------

export interface LearningLoopDeps {
  /** Get learning state for a provider/rule pair */
  getLearningState: (providerId: string, ruleId: string) => Promise<SelectAiProviderLearning | null>;
  /** Update priority adjustment for a provider/rule pair */
  updatePriorityAdjustment: (providerId: string, ruleId: string, adjustment: -1 | 0 | 1) => Promise<SelectAiProviderLearning | undefined>;
  /** Unsuppress a rule for a provider */
  unsuppressRule: (providerId: string, ruleId: string) => Promise<SelectAiProviderLearning | undefined>;
  /** Get suggestion events for a claim */
  getSuggestionEventsForClaim: (claimId: string) => Promise<{ eventId: string; claimId: string; suggestionId: string; ruleId: string | null; providerId: string; eventType: string; tier: number; category: string; revenueImpact: string | null; dismissedReason: string | null; createdAt: Date }[]>;
  /** Append a suggestion event */
  appendSuggestionEvent: (event: {
    claimId: string;
    suggestionId: string;
    ruleId?: string | null;
    providerId: string;
    eventType: string;
    tier: number;
    category: string;
    revenueImpact?: string | null;
    dismissedReason?: string | null;
  }) => Promise<unknown>;
  /** Get cohort defaults for a specialty + rule */
  getCohortDefaults: (specialtyCode: string, ruleId: string) => Promise<{ cohortId: string; specialtyCode: string; ruleId: string; physicianCount: number; acceptanceRate: string; medianRevenueImpact: string | null; updatedAt: Date } | null>;
  /** Recalculate all cohorts (delegates to repository) */
  recalculateAllCohorts: () => Promise<{ cohortId: string; specialtyCode: string; ruleId: string; physicianCount: number; acceptanceRate: string; medianRevenueImpact: string | null; updatedAt: Date }[]>;
  /** Delete cohorts below minimum size */
  deleteSmallCohorts: (minSize: number) => Promise<number>;
}

// ---------------------------------------------------------------------------
// Learning Loop: Priority Adjustment
// ---------------------------------------------------------------------------

/**
 * Recalculate priority adjustment for a provider/rule pair.
 *
 * Called after each accept/dismiss. Reads learning state and computes:
 * - acceptance_rate = times_accepted / times_shown
 * - If acceptance_rate > 0.70 AND times_shown >= 5 → priority_adjustment = +1 (promote)
 * - If acceptance_rate < 0.30 AND times_shown >= 5 → priority_adjustment = -1 (demote)
 * - Otherwise → priority_adjustment = 0
 *
 * Priority is never promoted above the rule-defined maximum (handled by evaluatePriority).
 */
export async function recalculatePriorityAdjustment(
  providerId: string,
  ruleId: string,
  deps: Pick<LearningLoopDeps, 'getLearningState' | 'updatePriorityAdjustment'>,
): Promise<number> {
  const state = await deps.getLearningState(providerId, ruleId);
  if (!state) return 0;

  const { timesShown, timesAccepted } = state;

  // Require minimum 5 observations before adjusting
  if (timesShown < 5) {
    if (state.priorityAdjustment !== 0) {
      await deps.updatePriorityAdjustment(providerId, ruleId, 0);
    }
    return 0;
  }

  const acceptanceRate = timesAccepted / timesShown;
  let adjustment: -1 | 0 | 1;

  if (acceptanceRate > 0.70) {
    adjustment = 1;
  } else if (acceptanceRate < 0.30) {
    adjustment = -1;
  } else {
    adjustment = 0;
  }

  if (state.priorityAdjustment !== adjustment) {
    await deps.updatePriorityAdjustment(providerId, ruleId, adjustment);
  }

  return adjustment;
}

// ---------------------------------------------------------------------------
// Learning Loop: Rejection Feedback
// ---------------------------------------------------------------------------

/**
 * Process rejection feedback when AHCIP/WCB returns a claim rejection.
 *
 * 1. Find DISMISSED suggestion events for this claim with category REJECTION_RISK.
 * 2. For each dismissed REJECTION_RISK suggestion that predicted this rejection:
 *    a. Re-enable the rule (unsuppress if suppressed).
 *    b. Set priority_adjustment = +1 permanently.
 *    c. Log a feedback event for learning analysis.
 */
export async function processRejectionFeedback(
  claimId: string,
  rejectionReason: string,
  deps: LearningLoopDeps,
): Promise<{ processedRuleIds: string[] }> {
  const events = await deps.getSuggestionEventsForClaim(claimId);

  // Find dismissed REJECTION_RISK events
  const dismissedRejectionEvents = events.filter(
    (e) =>
      e.eventType === SuggestionEventType.DISMISSED &&
      e.category === SuggestionCategory.REJECTION_RISK &&
      e.ruleId != null,
  );

  if (dismissedRejectionEvents.length === 0) {
    return { processedRuleIds: [] };
  }

  const processedRuleIds: string[] = [];

  for (const event of dismissedRejectionEvents) {
    const ruleId = event.ruleId!;
    const providerId = event.providerId;

    // a. Re-enable the rule (unsuppress if suppressed)
    const learningState = await deps.getLearningState(providerId, ruleId);
    if (learningState?.isSuppressed) {
      await deps.unsuppressRule(providerId, ruleId);
    }

    // b. Set priority_adjustment = +1 permanently
    await deps.updatePriorityAdjustment(providerId, ruleId, 1);

    // c. Log feedback event
    await deps.appendSuggestionEvent({
      claimId,
      suggestionId: event.suggestionId,
      ruleId,
      providerId,
      eventType: 'REJECTION_FEEDBACK',
      tier: event.tier,
      category: SuggestionCategory.REJECTION_RISK,
      dismissedReason: rejectionReason,
    });

    processedRuleIds.push(ruleId);
  }

  return { processedRuleIds };
}

// ---------------------------------------------------------------------------
// Learning Loop: Specialty Cohort Recalculation
// ---------------------------------------------------------------------------

/**
 * Recalculate specialty cohorts (nightly job).
 *
 * 1. Delegate to repository's recalculateAllCohorts which:
 *    a. For each (specialty, rule) in ai_provider_learning:
 *       - Count distinct providers (physician_count).
 *       - If physician_count >= 10: calculate aggregate acceptance_rate, median_revenue_impact.
 *       - Upsert into ai_specialty_cohorts.
 * 2. Delete cohorts with < 10 physicians (stale from previous runs).
 *
 * @returns The recalculated cohorts that meet the minimum size.
 */
export async function recalculateSpecialtyCohorts(
  deps: Pick<LearningLoopDeps, 'recalculateAllCohorts' | 'deleteSmallCohorts'>,
): Promise<{ cohorts: { specialtyCode: string; ruleId: string; physicianCount: number; acceptanceRate: string }[]; deletedCount: number }> {
  const cohorts = await deps.recalculateAllCohorts();
  const deletedCount = await deps.deleteSmallCohorts(MIN_COHORT_SIZE);

  return {
    cohorts: cohorts.map((c) => ({
      specialtyCode: c.specialtyCode,
      ruleId: c.ruleId,
      physicianCount: c.physicianCount,
      acceptanceRate: c.acceptanceRate,
    })),
    deletedCount,
  };
}

// ---------------------------------------------------------------------------
// Learning Loop: New Provider Initialisation
// ---------------------------------------------------------------------------

/**
 * Get default priority adjustment for a new provider based on specialty cohort.
 *
 * If a cohort exists for this specialty + rule with >= 10 physicians,
 * use the cohort's acceptance_rate to derive initial priority_adjustment:
 * - >0.70 → +1 (the specialty generally values this rule)
 * - <0.30 → -1 (the specialty generally dismisses this rule)
 * - Otherwise → 0
 *
 * If no qualifying cohort exists, return 0.
 */
export async function getDefaultPriorityForNewProvider(
  specialtyCode: string,
  ruleId: string,
  deps: Pick<LearningLoopDeps, 'getCohortDefaults'>,
): Promise<number> {
  const cohort = await deps.getCohortDefaults(specialtyCode, ruleId);
  if (!cohort) return 0;

  const acceptanceRate = parseFloat(cohort.acceptanceRate);
  if (isNaN(acceptanceRate)) return 0;

  if (acceptanceRate > 0.70) return 1;
  if (acceptanceRate < 0.30) return -1;
  return 0;
}

// ---------------------------------------------------------------------------
// SOMB Change Analysis Dependencies
// ---------------------------------------------------------------------------

/** A rule affected by a SOMB version change with its change type. */
export interface AffectedRule {
  ruleId: string;
  name: string;
  category: string;
  changeType: 'updated' | 'deprecated' | 'new';
}

/** Per-physician impact summary from a SOMB version change. */
export interface PhysicianImpact {
  providerId: string;
  affectedRules: AffectedRule[];
  affectedCodes: string[];
  estimatedRevenueImpact: number;
  plainLanguageSummary: string;
}

/** Result of analyseSombChange. */
export interface SombChangeResult {
  physicianImpacts: PhysicianImpact[];
  totalAffectedPhysicians: number;
  totalAffectedRules: number;
}

/** Dependencies for SOMB change analysis (injected, not imported). */
export interface SombChangeDeps {
  /** Get rules from the old SOMB version */
  getRulesByVersion: (sombVersion: string) => Promise<SelectAiRule[]>;
  /** Get provider learning for a set of rule IDs (used to find affected physicians) */
  getProviderLearningForRules: (providerId: string, ruleIds: string[]) => Promise<SelectAiProviderLearning[]>;
  /** Get all provider IDs with learning state for any of the given rules (times_shown > 0) */
  getPhysiciansUsingRules: (ruleIds: string[]) => Promise<{ providerId: string }[]>;
  /** Optional: emit notification event per affected physician */
  emitNotification?: (event: { eventType: string; physicianId: string; metadata?: Record<string, unknown> }) => Promise<void>;
  /** Optional: LLM client for generating plain language summary (Tier 2) */
  llmClient?: {
    chatCompletion: (messages: { role: string; content: string }[], options?: { temperature?: number }) => Promise<{ content: string | null }>;
  } | null;
}

// ---------------------------------------------------------------------------
// SOMB Change Analysis
// ---------------------------------------------------------------------------

/**
 * Compare SOMB versions and generate per-physician impact analysis.
 *
 * 1. Fetch rules with somb_version = oldVersion and newVersion.
 * 2. Identify changed/deprecated/new rules between versions.
 * 3. For each affected rule, find physicians who have used it (times_shown > 0).
 * 4. Generate per-physician impact summary with affected_rules, affected_codes,
 *    estimated_revenue_impact, and plain_language_summary.
 * 5. Emit SOMB_CHANGE_IMPACT notification per affected physician.
 */
export async function analyseSombChange(
  oldVersion: string,
  newVersion: string,
  deps: SombChangeDeps,
): Promise<SombChangeResult> {
  // 1. Fetch rules from both versions
  const [oldRules, newRules] = await Promise.all([
    deps.getRulesByVersion(oldVersion),
    deps.getRulesByVersion(newVersion),
  ]);

  // 2. Build lookup maps by rule name (rules with the same name across versions are the same rule)
  const oldRuleMap = new Map<string, SelectAiRule>();
  for (const rule of oldRules) {
    oldRuleMap.set(rule.name, rule);
  }

  const newRuleMap = new Map<string, SelectAiRule>();
  for (const rule of newRules) {
    newRuleMap.set(rule.name, rule);
  }

  // 3. Identify affected rules and their change type
  const affectedRules: AffectedRule[] = [];
  const allAffectedRuleIds: string[] = [];

  // Rules deprecated (in old, not in new)
  for (const [name, oldRule] of oldRuleMap) {
    if (!newRuleMap.has(name)) {
      affectedRules.push({
        ruleId: oldRule.ruleId,
        name: oldRule.name,
        category: oldRule.category,
        changeType: 'deprecated',
      });
      allAffectedRuleIds.push(oldRule.ruleId);
    }
  }

  // Rules updated (in both, but conditions or template changed)
  for (const [name, newRule] of newRuleMap) {
    const oldRule = oldRuleMap.get(name);
    if (oldRule) {
      const conditionsChanged = JSON.stringify(oldRule.conditions) !== JSON.stringify(newRule.conditions);
      const templateChanged = JSON.stringify(oldRule.suggestionTemplate) !== JSON.stringify(newRule.suggestionTemplate);
      if (conditionsChanged || templateChanged) {
        affectedRules.push({
          ruleId: oldRule.ruleId,
          name: newRule.name,
          category: newRule.category,
          changeType: 'updated',
        });
        allAffectedRuleIds.push(oldRule.ruleId);
      }
    }
  }

  // Rules new (in new, not in old)
  for (const [name, newRule] of newRuleMap) {
    if (!oldRuleMap.has(name)) {
      affectedRules.push({
        ruleId: newRule.ruleId,
        name: newRule.name,
        category: newRule.category,
        changeType: 'new',
      });
      allAffectedRuleIds.push(newRule.ruleId);
    }
  }

  if (affectedRules.length === 0) {
    return {
      physicianImpacts: [],
      totalAffectedPhysicians: 0,
      totalAffectedRules: 0,
    };
  }

  // 4. Find physicians who have used any of the affected rules
  const physicians = await deps.getPhysiciansUsingRules(allAffectedRuleIds);

  // 5. Build per-physician impact
  const physicianImpacts: PhysicianImpact[] = [];

  for (const { providerId } of physicians) {
    const learningStates = await deps.getProviderLearningForRules(providerId, allAffectedRuleIds);
    const usedRuleIds = new Set(
      learningStates
        .filter((ls) => ls.timesShown > 0)
        .map((ls) => ls.ruleId),
    );

    if (usedRuleIds.size === 0) continue;

    const physicianAffectedRules = affectedRules.filter((r) => usedRuleIds.has(r.ruleId));
    if (physicianAffectedRules.length === 0) continue;

    // Extract affected HSC codes from rule conditions (if field references HSC)
    const affectedCodes: string[] = [];
    for (const ar of physicianAffectedRules) {
      const rule = oldRuleMap.get(ar.name) ?? newRuleMap.get(ar.name);
      if (rule?.conditions) {
        const codes = extractHscCodesFromCondition(rule.conditions as Condition);
        for (const code of codes) {
          if (!affectedCodes.includes(code)) {
            affectedCodes.push(code);
          }
        }
      }
    }

    // Estimate revenue impact from learning states (median_revenue_impact from template)
    let estimatedRevenueImpact = 0;
    for (const ar of physicianAffectedRules) {
      const rule = oldRuleMap.get(ar.name) ?? newRuleMap.get(ar.name);
      if (rule?.suggestionTemplate) {
        const template = rule.suggestionTemplate as SuggestionTemplate;
        if (template.revenue_impact_formula) {
          const match = template.revenue_impact_formula.match(/fixed:([\d.]+)/);
          if (match) {
            estimatedRevenueImpact += parseFloat(match[1]) || 0;
          }
        }
      }
    }

    // Generate plain language summary
    let plainLanguageSummary: string;
    if (deps.llmClient) {
      try {
        const result = await deps.llmClient.chatCompletion([
          {
            role: 'system',
            content: 'You are a medical billing assistant. Generate a brief, physician-friendly summary of SOMB changes. No PHI. Keep it under 200 words.',
          },
          {
            role: 'user',
            content: `SOMB version change from ${oldVersion} to ${newVersion}. Affected rules: ${physicianAffectedRules.map((r) => `${r.name} (${r.changeType})`).join(', ')}. Affected codes: ${affectedCodes.join(', ') || 'none identified'}.`,
          },
        ], { temperature: 0.3 });
        plainLanguageSummary = result.content ?? generateTemplateSummary(oldVersion, newVersion, physicianAffectedRules, affectedCodes);
      } catch {
        plainLanguageSummary = generateTemplateSummary(oldVersion, newVersion, physicianAffectedRules, affectedCodes);
      }
    } else {
      plainLanguageSummary = generateTemplateSummary(oldVersion, newVersion, physicianAffectedRules, affectedCodes);
    }

    physicianImpacts.push({
      providerId,
      affectedRules: physicianAffectedRules,
      affectedCodes,
      estimatedRevenueImpact,
      plainLanguageSummary,
    });

    // 6. Emit notification event
    if (deps.emitNotification) {
      deps.emitNotification({
        eventType: 'SOMB_CHANGE_IMPACT',
        physicianId: providerId,
        metadata: {
          old_version: oldVersion,
          new_version: newVersion,
          affected_rule_count: physicianAffectedRules.length,
          affected_code_count: affectedCodes.length,
          estimated_revenue_impact: estimatedRevenueImpact.toFixed(2),
        },
      }).catch(() => {/* fire-and-forget notification */});
    }
  }

  return {
    physicianImpacts,
    totalAffectedPhysicians: physicianImpacts.length,
    totalAffectedRules: affectedRules.length,
  };
}

/**
 * Generate a template-based summary when LLM is unavailable.
 */
function generateTemplateSummary(
  oldVersion: string,
  newVersion: string,
  affectedRules: AffectedRule[],
  affectedCodes: string[],
): string {
  const updated = affectedRules.filter((r) => r.changeType === 'updated').length;
  const deprecated = affectedRules.filter((r) => r.changeType === 'deprecated').length;
  const newCount = affectedRules.filter((r) => r.changeType === 'new').length;

  const parts: string[] = [`SOMB updated from ${oldVersion} to ${newVersion}.`];

  if (updated > 0) parts.push(`${updated} rule(s) updated.`);
  if (deprecated > 0) parts.push(`${deprecated} rule(s) deprecated.`);
  if (newCount > 0) parts.push(`${newCount} new rule(s) added.`);
  if (affectedCodes.length > 0) {
    parts.push(`Affected codes: ${affectedCodes.join(', ')}.`);
  }
  parts.push('Review your billing practices for these changes.');

  return parts.join(' ');
}

/**
 * Extract HSC codes referenced in condition tree.
 * Looks for field_compare conditions that reference HSC-related fields.
 */
function extractHscCodesFromCondition(condition: Condition): string[] {
  const codes: string[] = [];

  if (condition.type === 'field_compare') {
    if (
      condition.field &&
      (condition.field.includes('healthServiceCode') || condition.field.includes('hscCode')) &&
      condition.value != null &&
      typeof condition.value === 'string'
    ) {
      codes.push(condition.value);
    }
  }

  if (condition.type === 'set_membership') {
    if (
      condition.field &&
      (condition.field.includes('healthServiceCode') || condition.field.includes('hscCode')) &&
      Array.isArray(condition.value)
    ) {
      for (const v of condition.value) {
        if (typeof v === 'string') codes.push(v);
      }
    }
  }

  if (condition.children && Array.isArray(condition.children)) {
    for (const child of condition.children) {
      codes.push(...extractHscCodesFromCondition(child as Condition));
    }
  }

  return codes;
}

// ---------------------------------------------------------------------------
// Contextual Help Dependencies
// ---------------------------------------------------------------------------

/** Help content returned from Reference Data. */
export interface HelpContent {
  helpText: string;
  sourceReference: string;
  sourceUrl: string | null;
}

/** Code detail with fee, modifiers, and governing rules. */
export interface CodeHelpDetail {
  hscCode: string;
  description: string;
  fee: string | null;
  eligibleModifiers: string[];
  applicableGoverningRules: { ruleId: string; title: string }[];
  tips: string[];
}

/** Governing rule summary. */
export interface GoverningRuleSummary {
  ruleId: string;
  title: string;
  plainLanguageSummary: string;
  officialLink: string | null;
}

/** Dependencies for contextual help (injected from Reference Data). */
export interface ContextualHelpDeps {
  /** Get field help text from Reference Data help registry */
  getFieldHelpText: (fieldName: string, context?: { hsc?: string; modifier?: string; formId?: string }) => Promise<HelpContent | null>;
  /** Get governing rule detail by GR number */
  getGoverningRule: (grNumber: string) => Promise<{
    ruleId: string;
    title: string;
    description: string;
    officialUrl: string | null;
  } | null>;
  /** Get HSC code detail including fee, modifiers, and applicable GRs */
  getHscCodeDetail: (hscCode: string) => Promise<{
    hscCode: string;
    description: string;
    fee: string | null;
    eligibleModifiers: string[];
    applicableGoverningRules: { ruleId: string; title: string }[];
    tips: string[];
  } | null>;
}

// ---------------------------------------------------------------------------
// Contextual Help: Field Help
// ---------------------------------------------------------------------------

/**
 * Get help content for a specific field. Content comes from Reference Data.
 * Context narrows help to a specific HSC code, modifier, or form if provided.
 * Intelligence Engine does NOT generate this content — it is read-only from Reference Data.
 */
export async function getFieldHelp(
  fieldName: string,
  deps: ContextualHelpDeps,
  context?: { hsc?: string; modifier?: string; formId?: string },
): Promise<HelpContent | null> {
  return deps.getFieldHelpText(fieldName, context);
}

// ---------------------------------------------------------------------------
// Contextual Help: Governing Rule Summary
// ---------------------------------------------------------------------------

/**
 * Get a plain-language governing rule summary with official link.
 * Content is read-only from Reference Data.
 */
export async function getGoverningRuleSummary(
  grNumber: string,
  deps: ContextualHelpDeps,
): Promise<GoverningRuleSummary | null> {
  const rule = await deps.getGoverningRule(grNumber);
  if (!rule) return null;

  return {
    ruleId: rule.ruleId,
    title: rule.title,
    plainLanguageSummary: rule.description,
    officialLink: rule.officialUrl,
  };
}

// ---------------------------------------------------------------------------
// Contextual Help: Code Help
// ---------------------------------------------------------------------------

/**
 * Get comprehensive help for an HSC code including:
 * - Code description and fee
 * - Eligible modifiers
 * - Applicable governing rules
 * - Billing tips
 *
 * Content is read-only from Reference Data.
 */
export async function getCodeHelp(
  hscCode: string,
  deps: ContextualHelpDeps,
): Promise<CodeHelpDetail | null> {
  return deps.getHscCodeDetail(hscCode);
}

// ---------------------------------------------------------------------------
// Export service factory
// ---------------------------------------------------------------------------

export function createIntelService(deps: ClaimContextDeps, tier1Deps?: Tier1Deps, lifecycleDeps?: LifecycleDeps, analyseDeps?: AnalyseDeps, learningLoopDeps?: LearningLoopDeps, sombChangeDeps?: SombChangeDeps, contextualHelpDeps?: ContextualHelpDeps) {
  return {
    buildClaimContext: (claimId: string, providerId: string) =>
      buildClaimContext(claimId, providerId, deps),

    evaluateCondition: (condition: Condition, context: ClaimContext) =>
      evaluateCondition(condition, context),

    prefetchCrossClaimData: (
      context: ClaimContext,
      conditions: Condition[],
      providerId: string,
      patientId: string,
    ) => prefetchCrossClaimData(context, conditions, providerId, patientId, deps),

    resolveField: (context: ClaimContext, path: string) =>
      resolveField(context, path),

    renderSuggestion: (
      rule: SelectAiRule,
      template: SuggestionTemplate,
      context: ClaimContext,
      priorityAdjustment: number,
    ) => renderSuggestion(rule, template, context, priorityAdjustment),

    evaluateTier1Rules: (claimId: string, providerId: string) => {
      if (!tier1Deps) throw new Error('Tier1Deps not provided to createIntelService');
      return evaluateTier1Rules(claimId, providerId, deps, tier1Deps);
    },

    generateTier3Suggestion: (
      trigger: string,
      context: ClaimContext,
      sourceReference: string,
      sourceUrl?: string,
    ) => generateTier3Suggestion(trigger, context, sourceReference, sourceUrl),

    acceptSuggestion: (claimId: string, suggestionId: string, providerId: string) => {
      if (!lifecycleDeps) throw new Error('LifecycleDeps not provided to createIntelService');
      return acceptSuggestion(claimId, suggestionId, providerId, lifecycleDeps);
    },

    dismissSuggestion: (claimId: string, suggestionId: string, providerId: string, reason?: string) => {
      if (!lifecycleDeps) throw new Error('LifecycleDeps not provided to createIntelService');
      return dismissSuggestion(claimId, suggestionId, providerId, lifecycleDeps, reason);
    },

    getClaimSuggestions: (claimId: string, providerId: string) => {
      if (!lifecycleDeps) throw new Error('LifecycleDeps not provided to createIntelService');
      return getClaimSuggestions(claimId, providerId, lifecycleDeps);
    },

    analyseClaim: (claimId: string, providerId: string) => {
      if (!analyseDeps) throw new Error('AnalyseDeps not provided to createIntelService');
      return analyseClaim(claimId, providerId, analyseDeps);
    },

    reanalyseClaim: (claimId: string, providerId: string) => {
      if (!analyseDeps) throw new Error('AnalyseDeps not provided to createIntelService');
      return reanalyseClaim(claimId, providerId, analyseDeps);
    },

    recalculatePriorityAdjustment: (providerId: string, ruleId: string) => {
      if (!learningLoopDeps) throw new Error('LearningLoopDeps not provided to createIntelService');
      return recalculatePriorityAdjustment(providerId, ruleId, learningLoopDeps);
    },

    processRejectionFeedback: (claimId: string, rejectionReason: string) => {
      if (!learningLoopDeps) throw new Error('LearningLoopDeps not provided to createIntelService');
      return processRejectionFeedback(claimId, rejectionReason, learningLoopDeps);
    },

    recalculateSpecialtyCohorts: () => {
      if (!learningLoopDeps) throw new Error('LearningLoopDeps not provided to createIntelService');
      return recalculateSpecialtyCohorts(learningLoopDeps);
    },

    getDefaultPriorityForNewProvider: (specialtyCode: string, ruleId: string) => {
      if (!learningLoopDeps) throw new Error('LearningLoopDeps not provided to createIntelService');
      return getDefaultPriorityForNewProvider(specialtyCode, ruleId, learningLoopDeps);
    },

    extractCrossClaimQueries,
    crossClaimQueryKey,

    analyseSombChange: (oldVersion: string, newVersion: string) => {
      if (!sombChangeDeps) throw new Error('SombChangeDeps not provided to createIntelService');
      return analyseSombChange(oldVersion, newVersion, sombChangeDeps);
    },

    getFieldHelp: (fieldName: string, context?: { hsc?: string; modifier?: string; formId?: string }) => {
      if (!contextualHelpDeps) throw new Error('ContextualHelpDeps not provided to createIntelService');
      return getFieldHelp(fieldName, contextualHelpDeps, context);
    },

    getGoverningRuleSummary: (grNumber: string) => {
      if (!contextualHelpDeps) throw new Error('ContextualHelpDeps not provided to createIntelService');
      return getGoverningRuleSummary(grNumber, contextualHelpDeps);
    },

    getCodeHelp: (hscCode: string) => {
      if (!contextualHelpDeps) throw new Error('ContextualHelpDeps not provided to createIntelService');
      return getCodeHelp(hscCode, contextualHelpDeps);
    },
  };
}

export type IntelService = ReturnType<typeof createIntelService>;
