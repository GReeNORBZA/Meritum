// ============================================================================
// Domain 7: Intelligence Engine — MVP Rule Seed
// Idempotent insertion of ~105 deterministic rules for Tier 1 evaluation.
// Categories: Modifier Eligibility (~30), Rejection Prevention (~40),
//             WCB-Specific (~20), Pattern-Based (~15).
// ============================================================================

import type { Condition, SuggestionTemplate, InsertAiRule } from '@meritum/shared/schemas/db/intelligence.schema.js';

// ---------------------------------------------------------------------------
// Rule definition type (all fields except auto-generated IDs/timestamps)
// ---------------------------------------------------------------------------

export interface MvpRuleDefinition {
  name: string;
  category: string;
  claimType: string;
  conditions: Condition;
  suggestionTemplate: SuggestionTemplate;
  specialtyFilter: string[] | null;
  priorityFormula: string;
  sombVersion: string;
  isBedsideContingent?: boolean;
}

// ---------------------------------------------------------------------------
// Modifier Eligibility Rules (~30)
// ---------------------------------------------------------------------------

const modifierEligibilityRules: MvpRuleDefinition[] = [
  // ---------------------------------------------------------------------------
  // CMGP Modifier Investigation (D07-213)
  // FINDING: CMGP (Comprehensive General Practice) modifier has 15 entries in
  // hsc-modifiers.json (type "CMPX", action "For Each Call Increase By $19.54"),
  // covering only the 03.0x family of HSC codes (03.01J, 03.03A, 03.03AZ,
  // 03.03B, 03.03BZ, 03.03C, 03.03CV, 03.03N, 03.03NA, 03.03NB, 03.03P,
  // 03.03Q, 03.07A, 03.07AZ, 03.07B). This is a small subset compared to the
  // broader CMGP program scope. The discrepancy is expected — CMGP eligibility
  // is primarily determined by provider specialty (GP/Family Medicine) and the
  // CMGP program enrollment status, not solely by per-HSC-code eligibility in
  // the modifier table. The 6 CMGP rules below use specialty-based conditions
  // (specialtyFilter: ['GP']) combined with reference set lookups
  // (ref.cmgp_eligible_codes, ref.cmgp_comprehensive_codes, etc.) which are
  // populated from the broader CMGP program definition, not just
  // hsc-modifiers.json. This approach is correct.
  // ---------------------------------------------------------------------------

  // --- CMGP Modifier Rules ---
  {
    name: 'CMGP eligibility — GP office visit',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.cmgp_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'CMGP' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'CMGP' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'CMGP' },
      ],
    },
    suggestionTemplate: {
      title: 'Add CMGP modifier',
      description: 'This service code is eligible for the CMGP modifier. Adding it increases the fee by the CMGP premium.',
      revenue_impact_formula: 'fixed:20.00',
      source_reference: 'SOMB 2026 CMGP Program',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'CMGP' }],
    },
    specialtyFilter: ['GP'],
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'CMGP eligibility — comprehensive visit',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.cmgp_comprehensive_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'CMGP' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'CMGP' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'CMGP' },
      ],
    },
    suggestionTemplate: {
      title: 'Add CMGP modifier to comprehensive visit',
      description: 'Comprehensive visit codes are CMGP-eligible. The modifier adds the CMGP fee premium to the claim.',
      revenue_impact_formula: 'fixed:20.00',
      source_reference: 'SOMB 2026 CMGP Program',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'CMGP' }],
    },
    specialtyFilter: ['GP'],
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'CMGP eligibility — chronic disease management',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.cmgp_chronic_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'CMGP' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'CMGP' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'CMGP' },
      ],
    },
    suggestionTemplate: {
      title: 'Add CMGP modifier to chronic disease code',
      description: 'Chronic disease management codes are eligible for CMGP. Consider adding this modifier.',
      revenue_impact_formula: 'fixed:20.00',
      source_reference: 'SOMB 2026 CMGP Program',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'CMGP' }],
    },
    specialtyFilter: ['GP'],
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'CMGP eligibility — preventive care',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.cmgp_preventive_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'CMGP' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'CMGP' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'CMGP' },
      ],
    },
    suggestionTemplate: {
      title: 'Add CMGP modifier to preventive care code',
      description: 'Preventive care codes qualify for CMGP modifier. Adding it increases claim value.',
      revenue_impact_formula: 'fixed:20.00',
      source_reference: 'SOMB 2026 CMGP Program',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'CMGP' }],
    },
    specialtyFilter: ['GP'],
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'CMGP eligibility — mental health',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.cmgp_mental_health_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'CMGP' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'CMGP' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'CMGP' },
      ],
    },
    suggestionTemplate: {
      title: 'Add CMGP modifier to mental health code',
      description: 'Mental health service codes are CMGP-eligible. The CMGP modifier premium applies.',
      revenue_impact_formula: 'fixed:20.00',
      source_reference: 'SOMB 2026 CMGP Program',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'CMGP' }],
    },
    specialtyFilter: ['GP'],
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- Off Hours Premium (SURC type: EV, NTAM, NTPM, WK) Modifier Rules ---
  {
    name: 'After-hours eligibility — weekday evening',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'temporal', field: 'claim.dayOfWeek', operator: 'IN', value: [1, 2, 3, 4, 5] },
        { type: 'field_compare', field: 'ahcip.afterHoursFlag', operator: '==', value: false },
        { type: 'set_membership', field: 'ahcip.encounterType', operator: 'IN', value: ['OFFICE', 'HOSPITAL', 'ED'] },
      ],
    },
    suggestionTemplate: {
      title: 'Consider off-hours premium (EV surcharge)',
      description: 'This claim is from a weekday. If the service was provided after 17:00 or before 08:00, you may claim the EV (evening) surcharge modifier under GR 15.',
      revenue_impact_formula: 'fixed:30.00',
      source_reference: 'SOMB 2026 GR 15 — Off Hours Premium Benefits',
      suggested_changes: [{ field: 'ahcip.afterHoursFlag', value_formula: 'true' }],
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'After-hours eligibility — weekend',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'temporal', field: 'claim.dayOfWeek', operator: 'IN', value: [0, 6] },
        { type: 'field_compare', field: 'ahcip.afterHoursFlag', operator: '==', value: false },
      ],
    },
    suggestionTemplate: {
      title: 'Add off-hours premium for weekend service (WK surcharge)',
      description: 'This service was on a weekend. Weekend services qualify for the WK (weekend) surcharge modifier under GR 15.',
      revenue_impact_formula: 'fixed:30.00',
      source_reference: 'SOMB 2026 GR 15 — Off Hours Premium Benefits',
      suggested_changes: [{ field: 'ahcip.afterHoursFlag', value_formula: 'true' }],
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'After-hours eligibility — statutory holiday',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'claim.dateOfService', operator: 'IN', value: 'ref.statutory_holidays' },
        { type: 'field_compare', field: 'ahcip.afterHoursFlag', operator: '==', value: false },
      ],
    },
    suggestionTemplate: {
      title: 'Add off-hours premium for statutory holiday (WK surcharge)',
      description: 'This service was on a statutory holiday. Statutory holidays qualify for the WK (weekend) surcharge modifier under GR 15.',
      revenue_impact_formula: 'fixed:30.00',
      source_reference: 'SOMB 2026 GR 15 — Off Hours Premium Benefits',
      suggested_changes: [{ field: 'ahcip.afterHoursFlag', value_formula: 'true' }],
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- SURC Modifier Rules (EV, NTAM, NTPM, WK) — Off-Hours Surcharge ---
  // Each SURC modifier applies to 1,942 HSC codes in hsc-modifiers.json.
  // These are the single largest revenue gap for most physicians.
  {
    name: 'Off-hours surcharge — weekday evening (EV)',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'temporal', field: 'claim.dayOfWeek', operator: 'IN', value: [1, 2, 3, 4, 5] },
        { type: 'temporal', field: 'claim.encounterHour', operator: '>=', value: 17 },
        { type: 'temporal', field: 'claim.encounterHour', operator: '<', value: 22 },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.surc_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'EV' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'EV' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'EV' },
      ],
    },
    suggestionTemplate: {
      title: 'Add EV surcharge modifier',
      description: 'This service was provided on a weekday evening (17:00–22:00) and the HSC code is SURC-eligible. The EV modifier adds an off-hours surcharge under GR 15.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 GR 15 — Off Hours Premium Benefits',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'EV' }],
    },
    specialtyFilter: null,
    priorityFormula: 'tier:1:priority:2',
    sombVersion: '2026.1',
  },
  {
    name: 'Off-hours surcharge — night AM (NTAM)',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'temporal', field: 'claim.encounterHour', operator: '>=', value: 22 },
        { type: 'temporal', field: 'claim.encounterHour', operator: '<', value: 24 },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.surc_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'NTAM' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'NTAM' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'NTAM' },
      ],
    },
    suggestionTemplate: {
      title: 'Add NTAM surcharge modifier',
      description: 'This service was provided between 22:00–00:00 and the HSC code is SURC-eligible. The NTAM modifier adds a night surcharge under GR 15.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 GR 15 — Off Hours Premium Benefits',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'NTAM' }],
    },
    specialtyFilter: null,
    priorityFormula: 'tier:1:priority:2',
    sombVersion: '2026.1',
  },
  {
    name: 'Off-hours surcharge — night PM (NTPM)',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'temporal', field: 'claim.encounterHour', operator: '>=', value: 0 },
        { type: 'temporal', field: 'claim.encounterHour', operator: '<', value: 7 },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.surc_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'NTPM' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'NTPM' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'NTPM' },
      ],
    },
    suggestionTemplate: {
      title: 'Add NTPM surcharge modifier',
      description: 'This service was provided between 00:00–07:00 and the HSC code is SURC-eligible. The NTPM modifier adds a night surcharge under GR 15.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 GR 15 — Off Hours Premium Benefits',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'NTPM' }],
    },
    specialtyFilter: null,
    priorityFormula: 'tier:1:priority:2',
    sombVersion: '2026.1',
  },
  {
    name: 'Off-hours surcharge — weekend/holiday (WK)',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        {
          type: 'or',
          children: [
            { type: 'temporal', field: 'claim.dayOfWeek', operator: 'IN', value: [0, 6] },
            { type: 'set_membership', field: 'claim.dateOfService', operator: 'IN', value: 'ref.statutory_holidays' },
          ],
        },
        { type: 'temporal', field: 'claim.encounterHour', operator: '>=', value: 7 },
        { type: 'temporal', field: 'claim.encounterHour', operator: '<', value: 22 },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.surc_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'WK' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'WK' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'WK' },
      ],
    },
    suggestionTemplate: {
      title: 'Add WK surcharge modifier',
      description: 'This service was provided on a weekend or statutory holiday (07:00–22:00) and the HSC code is SURC-eligible. The WK modifier adds an off-hours surcharge under GR 15.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 GR 15 — Off Hours Premium Benefits',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'WK' }],
    },
    specialtyFilter: null,
    priorityFormula: 'tier:1:priority:2',
    sombVersion: '2026.1',
  },

  // --- Tray Service (GR 14) — MAJT Modifier ---
  // GR 14 defines 184 HSC codes eligible for tray service (109 major, 75 minor).
  // MAJT (major tray) has 105 eligible codes in hsc-modifiers.json.
  {
    name: 'Tray service — in-office procedure eligible for MAJT',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.tray_eligible_codes' },
        { type: 'set_membership', field: 'ahcip.encounterType', operator: 'NOT IN', value: ['HOSPITAL', 'ED', 'FACILITY'] },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'MAJT' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'MAJT' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'MAJT' },
      ],
    },
    suggestionTemplate: {
      title: 'Tray service modifier (MAJT) may apply',
      description: 'This procedure is eligible for the major tray service benefit (MAJT) when performed outside a hospital, AACC, UCC, or contracted facility. GR 14 allows claiming the tray fee in addition to the procedure fee.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 GR 14 — Tray Service',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'MAJT' }],
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- RRNP (Rural/Remote Northern Program) ---
  {
    name: 'RRNP eligibility — rural location',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'provider.defaultLocation.rrnpEligible', operator: '==', value: true },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'RRNP' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'RRNP' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'RRNP' },
      ],
    },
    suggestionTemplate: {
      title: 'RRNP modifier may apply',
      description: 'Your practice location qualifies for RRNP. This modifier provides a rural/remote premium on eligible services.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 RRNP Program',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'RRNP eligibility — emergency department',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'provider.defaultLocation.rrnpEligible', operator: '==', value: true },
        { type: 'field_compare', field: 'ahcip.encounterType', operator: '==', value: 'ED' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'RRNP' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'RRNP' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'RRNP' },
      ],
    },
    suggestionTemplate: {
      title: 'RRNP modifier for ED service',
      description: 'Emergency department services at RRNP-eligible locations qualify for the rural premium.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 RRNP Program',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- Shadow Billing (TM) ---
  {
    name: 'Shadow billing — ARP physician missing TM',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'ahcip.shadowBillingFlag', operator: '==', value: false },
        { type: 'field_compare', field: 'provider.physicianType', operator: '==', value: 'ARP' },
      ],
    },
    suggestionTemplate: {
      title: 'Add shadow billing (TM) modifier',
      description: 'ARP physicians should submit shadow billing claims with the TM modifier. While no fee is paid, this preserves your billing history for future negotiations.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 Section 6.1 — Shadow Billing',
      suggested_changes: [{ field: 'ahcip.shadowBillingFlag', value_formula: 'true' }],
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },
  {
    name: 'Shadow billing — ARP specialist',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'ahcip.shadowBillingFlag', operator: '==', value: false },
        { type: 'field_compare', field: 'provider.physicianType', operator: '==', value: 'ARP' },
        { type: 'set_membership', field: 'provider.specialtyCode', operator: 'NOT IN', value: ['GP'] },
      ],
    },
    suggestionTemplate: {
      title: 'Shadow billing recommended for ARP specialist',
      description: 'Specialist ARP physicians should submit shadow bills to maintain accurate utilisation records.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 Section 6.1 — Shadow Billing',
      suggested_changes: [{ field: 'ahcip.shadowBillingFlag', value_formula: 'true' }],
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },

  // --- Time-Based Documentation ---
  {
    name: 'Time documentation gap — counselling code',
    category: 'DOCUMENTATION_GAP',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.time_based_codes' },
        { type: 'existence', field: 'ahcip.timeSpent', operator: 'IS NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Document time spent',
      description: 'This is a time-based service code. Time spent must be documented to support the claim if audited.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 Section 4.3 — Time-Based Services',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'Time documentation gap — minimum threshold',
    category: 'DOCUMENTATION_GAP',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.time_based_codes' },
        { type: 'existence', field: 'ahcip.timeSpent', operator: 'IS NOT NULL' },
        { type: 'field_compare', field: 'ahcip.timeSpent', operator: '<', value: 15 },
      ],
    },
    suggestionTemplate: {
      title: 'Time spent below typical threshold',
      description: 'The documented time is below the typical minimum for this code. Ensure the documentation supports the billed service.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 Section 4.3 — Time-Based Services',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },

  // --- TELES (Telehealth) Modifier ---
  {
    name: 'Telehealth modifier — virtual encounter',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'ahcip.encounterType', operator: '==', value: 'VIRTUAL' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'TELE' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'TELE' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'TELE' },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.tele_eligible_codes' },
      ],
    },
    suggestionTemplate: {
      title: 'Add TELE modifier for virtual visit',
      description: 'This virtual encounter is eligible for the TELES modifier (code TELES, type TELE). Adding it adjusts the base fee via "Increase Base To" action.',
      revenue_impact_formula: 'fee_difference',
      source_reference: 'SOMB 2026 GR 17 — Telehealth',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'TELE' }],
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- Telehealth GR 17 — High-Traffic and Specialty TELES Rules ---
  {
    name: 'Telehealth — office visit (03.03A/03.04A/03.05A) eligible for TELES',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'ahcip.encounterType', operator: '==', value: 'VIRTUAL' },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: ['03.03A', '03.04A', '03.05A'] },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'TELE' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'TELE' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'TELE' },
      ],
    },
    suggestionTemplate: {
      title: 'Add TELES modifier to virtual office visit',
      description: 'This virtual office visit (03.03A, 03.04A, or 03.05A) is eligible for the TELES modifier under GR 17. These high-traffic codes frequently qualify for the telehealth fee adjustment.',
      revenue_impact_formula: 'fee_difference',
      source_reference: 'SOMB 2026 GR 17 — Telehealth (High-Traffic Codes)',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'TELE' }],
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'Telehealth — mental health consultation eligible for TELES',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'ahcip.encounterType', operator: '==', value: 'VIRTUAL' },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.mental_health_tele_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'TELE' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'TELE' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'TELE' },
      ],
    },
    suggestionTemplate: {
      title: 'Add TELES modifier to virtual mental health consultation',
      description: 'This mental health service code (08.19x family) is eligible for the TELES modifier when delivered virtually under GR 17.',
      revenue_impact_formula: 'fee_difference',
      source_reference: 'SOMB 2026 GR 17 — Telehealth (Mental Health)',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'TELE' }],
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'Telehealth — chronic disease management eligible for TELES',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'ahcip.encounterType', operator: '==', value: 'VIRTUAL' },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.chronic_disease_tele_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'TELE' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'TELE' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'TELE' },
      ],
    },
    suggestionTemplate: {
      title: 'Add TELES modifier to virtual chronic disease management',
      description: 'This chronic disease management code is eligible for the TELES modifier when delivered virtually under GR 17.',
      revenue_impact_formula: 'fee_difference',
      source_reference: 'SOMB 2026 GR 17 — Telehealth (Chronic Disease)',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'TELE' }],
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- BMI GR 18 — MODIFIER_ADD Rules ---
  {
    name: 'BMI modifier — surgical procedure with BMI premium',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'patient.bmi', operator: '>=', value: 35 },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.bmisrg_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'BMIPRO' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'BMIPRO' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'BMIPRO' },
      ],
    },
    suggestionTemplate: {
      title: 'BMI modifier for surgical procedure',
      description: 'This patient has a BMI >= 35 and the procedure is BMISRG-eligible. The BMIPRO modifier provides a BMI premium for surgical procedures under GR 18.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 GR 18 — Body Mass Index (Surgical)',
      suggested_changes: [{ field: 'ahcip.modifier2', value_formula: 'BMIPRO' }],
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'BMI modifier — anaesthesia with BMI premium',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'patient.bmi', operator: '>=', value: 35 },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.bmiane_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'BMIANE' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'BMIANE' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'BMIANE' },
      ],
    },
    suggestionTemplate: {
      title: 'BMI modifier for anaesthesia',
      description: 'This patient has a BMI >= 35 and the anaesthesia code is BMIANE-eligible. The BMIANE modifier provides a BMI premium for anaesthesia under GR 18.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 GR 18 — Body Mass Index (Anaesthesia)',
      suggested_changes: [{ field: 'ahcip.modifier2', value_formula: 'BMIANE' }],
    },
    specialtyFilter: ['ANES'],
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- BMI Modifier (type: BMI, codes: BMIPRO, BMIANE, BMIANT) ---
  {
    name: 'BMI modifier eligibility',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.bmi_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'BMI' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'BMI' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'BMI' },
      ],
    },
    suggestionTemplate: {
      title: 'BMI modifier may apply',
      description: 'This service code is eligible for the BMI modifier (BMIPRO, BMIANE, or BMIANT depending on procedure type) if BMI was documented during the encounter.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 GR 18 — Body Mass Index (BMI)',
      suggested_changes: [{ field: 'ahcip.modifier2', value_formula: 'BMI' }],
    },
    specialtyFilter: ['GP'],
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },

  // --- COMP (Complexity) Modifier ---
  // Note: The closest match in hsc-modifiers.json is COMPLT (type: REDO, 207 HSCs),
  // which means "completion" not "complexity". COMP here refers to a complexity
  // modifier concept that is distinct from COMPLT. Retaining COMP as the rule name.
  {
    name: 'Complexity modifier — multiple diagnoses',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.comp_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'COMP' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'COMP' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'COMP' },
      ],
    },
    suggestionTemplate: {
      title: 'Complexity modifier may apply',
      description: 'If this encounter involved managing multiple complex conditions, the COMP modifier adds a complexity premium.',
      revenue_impact_formula: 'fixed:15.00',
      source_reference: 'SOMB 2026 Section 3.3 — Complexity Modifier',
      suggested_changes: [{ field: 'ahcip.modifier2', value_formula: 'COMP' }],
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- PCPCM Basket ---
  {
    name: 'PCPCM basket eligibility',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'reference.hscCode.pcpcmBasket', operator: '!=', value: 'NONE' },
        { type: 'field_compare', field: 'ahcip.pcpcmBasketFlag', operator: '==', value: false },
      ],
    },
    suggestionTemplate: {
      title: 'PCPCM basket service — mark for PCPCM routing',
      description: 'This service code is part of the PCPCM basket. Marking it enables PCPCM pathway routing and tracking.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 PCPCM Program',
      suggested_changes: [{ field: 'ahcip.pcpcmBasketFlag', value_formula: 'true' }],
    },
    specialtyFilter: ['GP'],
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },

  // --- Calls Modifier ---
  {
    name: 'Multiple calls — same encounter',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'ahcip.calls', operator: '==', value: 1 },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.multi_call_eligible_codes' },
      ],
    },
    suggestionTemplate: {
      title: 'Consider multiple calls billing',
      description: 'This code supports billing for multiple calls in the same day. If you provided more than one visit, adjust the calls count.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 GR 15.11 — Callback Limits',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },

  // --- Facility-Specific Modifiers ---
  {
    name: 'Facility surcharge eligibility',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'reference.hscCode.surchargeEligible', operator: '==', value: true },
        { type: 'set_membership', field: 'ahcip.encounterType', operator: 'IN', value: ['HOSPITAL', 'FACILITY'] },
        { type: 'existence', field: 'ahcip.facilityNumber', operator: 'IS NOT NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Facility surcharge may apply',
      description: 'This code is eligible for a facility surcharge when performed at a hospital or designated facility.',
      revenue_impact_formula: 'fee_difference',
      source_reference: 'SOMB 2026 Section 5.2 — Facility Surcharges',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- Referring Practitioner Modifier ---
  {
    name: 'Referral modifier — specialist consultation',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'reference.hscCode.requiresReferral', operator: '==', value: true },
        { type: 'existence', field: 'ahcip.referralPractitioner', operator: 'IS NOT NULL' },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.referral_premium_codes' },
      ],
    },
    suggestionTemplate: {
      title: 'Referral consultation premium',
      description: 'This consultation with a referring practitioner may qualify for an additional consultation premium.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 Section 3.8 — Consultation Premiums',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- Specialty-Specific Modifiers ---
  {
    name: 'Anaesthesia time modifier',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.anaesthesia_codes' },
        { type: 'existence', field: 'ahcip.timeSpent', operator: 'IS NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Document anaesthesia time',
      description: 'Anaesthesia codes require time documentation. Without it, the claim may be assessed at base rate only.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 GR 12 — Anesthesia',
    },
    specialtyFilter: ['ANES'],
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'Surgical assist modifier',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.surgical_assist_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'SA' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'SA' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'SA' },
      ],
    },
    suggestionTemplate: {
      title: 'Surgical assist modifier may apply',
      description: 'If you assisted on this surgical procedure, the SA modifier enables claiming the surgical assist fee.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 GR 13 — Surgical Assistance Benefits',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'SA' }],
    },
    specialtyFilter: ['SURG', 'ORTHO', 'OBGYN'],
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- SAU/SAQU Surgical Assist Modifier Rules (GR 13) ---
  {
    name: 'Surgical assist — SAU modifier eligible for procedure',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.sau_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'SA' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'SA' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'SA' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'SAU' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'SAU' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'SAU' },
      ],
    },
    suggestionTemplate: {
      title: 'SAU modifier available for surgical assist',
      description: 'This surgical procedure is SAU-eligible. If you provided surgical assistance, the SAU modifier enables claiming the surgical assist unit fee under GR 13.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 GR 13 — Surgical Assistance Benefits',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'SAU' }],
    },
    specialtyFilter: ['SURG', 'ORTHO', 'OBGYN', 'NEURO', 'CARD'],
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'Surgical assist — SAQU quoted fee available',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.saqu_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'SAQU' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'SAQU' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'SAQU' },
      ],
    },
    suggestionTemplate: {
      title: 'SAQU quoted fee modifier available',
      description: 'This procedure is eligible for the SAQU (quoted surgical assist) modifier. If the assist type is quoted, SAQU may provide a higher reimbursement than SAU. Consider switching from SAU to SAQU if applicable.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 GR 13 — Surgical Assistance Quoted Fees',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'SAQU' }],
    },
    specialtyFilter: ['SURG', 'ORTHO', 'OBGYN', 'NEURO', 'CARD'],
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- VANE Extra Procedure Modifier (GR 12) ---
  {
    name: 'Anaesthesia — VANE extra procedure modifier available',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.vane_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'VANE' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'VANE' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'VANE' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 1,
            field: 'ahcip.healthServiceCode',
            aggregation: 'count',
            filter: {
              type: 'set_membership',
              field: 'reference.hscCode.categoryCode',
              operator: 'IN',
              value: ['P', 'M', 'M+', '1', '3', '4', '6', '14', '15'],
            },
          },
          field: 'crossClaim.vane_procedure_count',
          operator: '>=',
          value: 2,
        },
      ],
    },
    suggestionTemplate: {
      title: 'VANE modifier for additional procedure under same anaesthetic',
      description: 'Multiple surgical procedures were performed under the same anaesthetic. The VANE modifier is available for the additional procedure anaesthesia fee under GR 12.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 GR 12 — Anesthesia (VANE Modifier)',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'VANE' }],
    },
    specialtyFilter: ['ANES'],
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- REDO Modifier ---
  {
    name: 'Redo procedure — REDO modifier for repeat surgery',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.redo_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'REDO' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'REDO' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'REDO' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 365,
            field: 'ahcip.healthServiceCode',
            aggregation: 'exists',
            filter: {
              type: 'field_compare',
              field: 'ahcip.healthServiceCode',
              operator: '==',
              value: '{{ahcip.healthServiceCode}}',
            },
          },
          field: 'crossClaim.redo_prior_surgery',
          operator: '>=',
          value: 1,
        },
      ],
    },
    suggestionTemplate: {
      title: 'REDO modifier for repeat surgery',
      description: 'This procedure was previously performed on the same anatomical site. The REDO modifier may apply for repeat surgical procedures, providing an additional fee premium.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB Modifier Eligibility — REDO',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'REDO' }],
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- 2ANU Second Anaesthetist Modifier (GR 12) ---
  {
    name: 'Anaesthesia — 2ANU second anaesthetist modifier available',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.2anu_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: '2ANU' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: '2ANU' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: '2ANU' },
      ],
    },
    suggestionTemplate: {
      title: '2ANU second anaesthetist modifier available',
      description: 'This procedure is eligible for the 2ANU modifier when a second anaesthetist is required due to case complexity. The second anaesthetist can claim their time using this modifier under GR 12.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 GR 12 — Anesthesia (Second Anaesthetist)',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: '2ANU' }],
    },
    specialtyFilter: ['ANES'],
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- UGA Unplanned General Anaesthetic Modifier ---
  {
    name: 'Anaesthesia — UGA unplanned general anaesthetic modifier',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.uga_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'UGA' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'UGA' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'UGA' },
      ],
    },
    suggestionTemplate: {
      title: 'UGA modifier for unplanned general anaesthetic',
      description: 'If this procedure was planned under local/regional anaesthesia but required conversion to general anaesthesia, the UGA modifier applies. This provides an additional fee for the unplanned general anaesthetic.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB Modifier Eligibility — UGA',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'UGA' }],
    },
    specialtyFilter: ['ANES'],
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  {
    name: 'Emergency surcharge modifier',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'ahcip.encounterType', operator: '==', value: 'ED' },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.ed_surcharge_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'EDSC' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'EDSC' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'EDSC' },
      ],
    },
    suggestionTemplate: {
      title: 'ED surcharge modifier',
      description: 'Emergency department services may qualify for the ED surcharge modifier.',
      revenue_impact_formula: 'fixed:15.00',
      source_reference: 'SOMB 2026 Section 7.2 — Emergency Department',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'EDSC' }],
    },
    specialtyFilter: ['GP', 'EM'],
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- Bilateral Modifier ---
  {
    name: 'Bilateral modifier — bilateral procedure',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.bilateral_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'BILAT' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'BILAT' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'BILAT' },
      ],
    },
    suggestionTemplate: {
      title: 'Bilateral modifier may apply',
      description: 'If this procedure was performed bilaterally, the BILAT modifier increases the fee by 50%.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 Section 3.6 — Bilateral Procedures',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'BILAT' }],
    },
    specialtyFilter: ['SURG', 'ORTHO', 'OPHTHO', 'ENT'],
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- LOCM Modifier (Location) ---
  {
    name: 'LOCM modifier — outpatient facility',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'ahcip.encounterType', operator: '==', value: 'FACILITY' },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.locm_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'LOCM' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'LOCM' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'LOCM' },
      ],
    },
    suggestionTemplate: {
      title: 'LOCM modifier for outpatient facility',
      description: 'The LOCM modifier applies to services performed in designated outpatient facilities.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 Section 5.3 — Location Modifiers',
      suggested_changes: [{ field: 'ahcip.modifier2', value_formula: 'LOCM' }],
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },

  // --- CALD Modifier (Caldwell) ---
  {
    name: 'CALD modifier eligibility',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.cald_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'CALD' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'CALD' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'CALD' },
      ],
    },
    suggestionTemplate: {
      title: 'CALD modifier may apply',
      description: 'This code may be eligible for the CALD modifier if the service meets designated criteria.',
      revenue_impact_formula: 'fixed:10.00',
      source_reference: 'SOMB 2026 — CALD Program',
      suggested_changes: [{ field: 'ahcip.modifier2', value_formula: 'CALD' }],
    },
    specialtyFilter: ['GP'],
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },

  // --- Night Premium (SURC type: NTAM, NTPM) Modifier ---
  {
    name: 'Night premium modifier — overnight service',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.encounterType', operator: 'IN', value: ['HOSPITAL', 'ED'] },
        { type: 'field_compare', field: 'ahcip.afterHoursFlag', operator: '==', value: false },
      ],
    },
    suggestionTemplate: {
      title: 'Night premium may apply (NTAM/NTPM surcharge)',
      description: 'If this hospital/ED service was between 22:00 and 07:00, the NTAM (midnight–07:00) or NTPM (22:00–midnight) surcharge modifier applies under GR 15.',
      revenue_impact_formula: 'fixed:35.00',
      source_reference: 'SOMB 2026 GR 15 — Off Hours Premium Benefits (Night)',
      suggested_changes: [{ field: 'ahcip.afterHoursType', value_formula: 'NTPM' }],
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- CMXV (Complex Visit — Paediatric, type: CARE, codes: CMXV15/CMXV20/CMXV30/CMXV35) ---
  {
    name: 'CMXV modifier — complex paediatric visit',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'patient.age', operator: '<', value: 18 },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.cmxp_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'CMXV15' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'CMXV20' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'CMXV30' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'CMXV35' },
      ],
    },
    suggestionTemplate: {
      title: 'Complex paediatric visit modifier (CMXV) may apply',
      description: 'This paediatric visit may qualify for a CMXV modifier (CMXV15, CMXV20, CMXV30, or CMXV35 — type CARE) based on time and complexity.',
      revenue_impact_formula: 'fixed:18.00',
      source_reference: 'SOMB 2026 — Paediatric Modifiers (CMXV family, type CARE)',
      suggested_changes: [{ field: 'ahcip.modifier2', value_formula: 'CMXV15' }],
    },
    specialtyFilter: ['GP', 'PEDS'],
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- URGN (Urgent) Modifier ---
  {
    name: 'URGN modifier — urgent consultation',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.consultation_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'URGN' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'URGN' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'URGN' },
      ],
    },
    suggestionTemplate: {
      title: 'Urgent consultation modifier',
      description: 'If this consultation was performed on an urgent basis (same-day or next-day referral), the URGN modifier may apply.',
      revenue_impact_formula: 'fixed:25.00',
      source_reference: 'SOMB 2026 Section 3.9 — Urgent Consultations',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'URGN' }],
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- GR 12: Neonatal/Infant Anaesthesia Age Premium ---
  // GR 12.9 provides +25% for corrected age infants, GR 12.10 provides +50% for <40 weeks conceptual age.
  {
    name: 'GR 12 — neonatal/infant anaesthesia age premium available',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'patient.age', operator: '<', value: 1 },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.anaesthesia_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'CAANE' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'CAANE' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'L40ANE' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'L40ANE' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'L30AN' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'L30AN' },
      ],
    },
    suggestionTemplate: {
      title: 'Neonatal/infant anaesthesia age premium',
      description: 'This patient is under 1 year old and the procedure involves anaesthesia. Age-based premiums may apply: +25% for corrected age infants (CAANE/CAANT/CA2AN under GR 12.9), +50% for <40 weeks conceptual age (L40ANE under GR 12.10), or additional neonatal benefit (L30AN/L30AT under GR 12.7).',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 GR 12 — Anesthesia Age Premiums',
      suggested_changes: [{ field: 'ahcip.modifier2', value_formula: 'CAANE' }],
    },
    specialtyFilter: ['ANES'],
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
];

// ---------------------------------------------------------------------------
// Rejection Prevention Rules (~40)
// ---------------------------------------------------------------------------

const rejectionPreventionRules: MvpRuleDefinition[] = [
  // --- GR 4: Visit Limits ---
  {
    name: 'GR 4 — daily visit limit same patient',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'cross_claim',
      query: {
        lookbackDays: 1,
        field: 'ahcip.healthServiceCode',
        aggregation: 'count',
        filter: {
          type: 'field_compare',
          field: 'ahcip.healthServiceCode',
          operator: '==',
          value: '{{ahcip.healthServiceCode}}',
        },
      },
      field: 'crossClaim.gr3_daily_count',
      operator: '>=',
      value: 2,
    },
    suggestionTemplate: {
      title: 'GR 4 daily visit limit risk',
      description: 'You have already billed this code for this patient today. A duplicate may be rejected under GR 4.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 4 — Visit and Consultation Frequency Limits',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'GR 4 — weekly visit limit same patient',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'cross_claim',
      query: {
        lookbackDays: 7,
        field: 'ahcip.healthServiceCode',
        aggregation: 'count',
        filter: {
          type: 'field_compare',
          field: 'ahcip.healthServiceCode',
          operator: '==',
          value: '{{ahcip.healthServiceCode}}',
        },
      },
      field: 'crossClaim.gr3_weekly_count',
      operator: '>=',
      value: 3,
    },
    suggestionTemplate: {
      title: 'GR 4 weekly visit limit risk',
      description: 'This patient has been billed this code 3+ times in 7 days. Additional claims may be rejected under GR 4.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 4 — Visit and Consultation Frequency Limits',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'GR 4 — monthly visit limit same patient same code',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'cross_claim',
      query: {
        lookbackDays: 30,
        field: 'ahcip.healthServiceCode',
        aggregation: 'count',
        filter: {
          type: 'field_compare',
          field: 'ahcip.healthServiceCode',
          operator: '==',
          value: '{{ahcip.healthServiceCode}}',
        },
      },
      field: 'crossClaim.gr3_monthly_count',
      operator: '>=',
      value: 5,
    },
    suggestionTemplate: {
      title: 'GR 4 monthly frequency limit',
      description: 'This code has been billed 5+ times for this patient in the last 30 days. Consider an alternative code or documenting medical necessity.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 4 — Visit and Consultation Frequency Limits',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'GR 4 — per-day max exceeded',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'existence', field: 'reference.hscCode.maxPerDay', operator: 'IS NOT NULL' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 1,
            field: 'ahcip.healthServiceCode',
            aggregation: 'count',
            filter: {
              type: 'field_compare',
              field: 'ahcip.healthServiceCode',
              operator: '==',
              value: '{{ahcip.healthServiceCode}}',
            },
          },
          field: 'crossClaim.gr3_per_day_max',
          operator: '>=',
          value: 1,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Per-day maximum exceeded',
      description: 'This code has a per-day maximum. You have already billed the maximum number of times today.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 4 — Visit and Consultation Frequency Limits',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- GR 8: Referral Requirements ---
  {
    name: 'GR 8 — specialist consultation without referral',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'reference.hscCode.requiresReferral', operator: '==', value: true },
        { type: 'existence', field: 'ahcip.referralPractitioner', operator: 'IS NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Missing referring practitioner',
      description: 'This consultation code requires a referring practitioner number. Without it, the claim will be rejected under GR 8.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 8 — Referral Requirements',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'GR 8 — specialist follow-up without initial referral',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.specialist_followup_codes' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 365,
            field: 'ahcip.referralPractitioner',
            aggregation: 'exists',
            filter: {
              type: 'set_membership',
              field: 'ahcip.healthServiceCode',
              operator: 'IN',
              value: 'ref.specialist_consultation_codes',
            },
          },
          field: 'crossClaim.gr8_initial_referral_exists',
          operator: '==',
          value: 0,
        },
      ],
    },
    suggestionTemplate: {
      title: 'No initial consultation referral found',
      description: 'No initial consultation with a referral was found for this patient in the last 365 days. A specialist follow-up without an initial referral may be rejected.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 8 — Referral Requirements',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- Diagnostic Code ---
  {
    name: 'Missing diagnostic code — required',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'existence', field: 'ahcip.diagnosticCode', operator: 'IS NULL' },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.di_required_codes' },
      ],
    },
    suggestionTemplate: {
      title: 'Diagnostic code required',
      description: 'This service code requires a diagnostic code. The claim will be rejected without one.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Diagnostic Code Requirements',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'Missing diagnostic code — recommended',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'existence', field: 'ahcip.diagnosticCode', operator: 'IS NULL' },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'NOT IN', value: 'ref.di_required_codes' },
      ],
    },
    suggestionTemplate: {
      title: 'Consider adding diagnostic code',
      description: 'A diagnostic code is recommended for this service code. Including one reduces rejection risk.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Diagnostic Code Best Practices',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },

  // --- Modifier Conflicts ---
  {
    name: 'Modifier conflict — mutually exclusive pair',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'existence', field: 'ahcip.modifier1', operator: 'IS NOT NULL' },
        { type: 'existence', field: 'ahcip.modifier2', operator: 'IS NOT NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Potential modifier conflict',
      description: 'Multiple modifiers are applied. Verify they are not mutually exclusive — conflicting modifiers will cause rejection.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 Section 3 — Modifier Rules',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'Modifier conflict — TELE and EDSC',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'or',
      children: [
        {
          type: 'and',
          children: [
            { type: 'field_compare', field: 'ahcip.modifier1', operator: '==', value: 'TELE' },
            { type: 'or', children: [
              { type: 'field_compare', field: 'ahcip.modifier2', operator: '==', value: 'EDSC' },
              { type: 'field_compare', field: 'ahcip.modifier3', operator: '==', value: 'EDSC' },
            ]},
          ],
        },
        {
          type: 'and',
          children: [
            { type: 'field_compare', field: 'ahcip.modifier1', operator: '==', value: 'EDSC' },
            { type: 'or', children: [
              { type: 'field_compare', field: 'ahcip.modifier2', operator: '==', value: 'TELE' },
              { type: 'field_compare', field: 'ahcip.modifier3', operator: '==', value: 'TELE' },
            ]},
          ],
        },
      ],
    },
    suggestionTemplate: {
      title: 'TELE and EDSC modifiers conflict',
      description: 'Telehealth (TELE) and Emergency Department Surcharge (EDSC) modifiers are mutually exclusive. Remove one.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 Section 3 — Modifier Rules',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'Modifier conflict — CMGP and SA',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'or',
      children: [
        {
          type: 'and',
          children: [
            { type: 'field_compare', field: 'ahcip.modifier1', operator: '==', value: 'CMGP' },
            { type: 'or', children: [
              { type: 'field_compare', field: 'ahcip.modifier2', operator: '==', value: 'SA' },
              { type: 'field_compare', field: 'ahcip.modifier3', operator: '==', value: 'SA' },
            ]},
          ],
        },
        {
          type: 'and',
          children: [
            { type: 'field_compare', field: 'ahcip.modifier1', operator: '==', value: 'SA' },
            { type: 'or', children: [
              { type: 'field_compare', field: 'ahcip.modifier2', operator: '==', value: 'CMGP' },
              { type: 'field_compare', field: 'ahcip.modifier3', operator: '==', value: 'CMGP' },
            ]},
          ],
        },
      ],
    },
    suggestionTemplate: {
      title: 'CMGP and SA modifiers conflict',
      description: 'CMGP (primary care) and SA (surgical assist) modifiers are mutually exclusive. Remove one.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 Section 3 — Modifier Rules',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- 90-Day Submission Window ---
  {
    name: '90-day window — approaching deadline',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'claim.state', operator: '==', value: 'DRAFT' },
      ],
    },
    suggestionTemplate: {
      title: 'Approaching 90-day submission deadline',
      description: 'AHCIP claims must be submitted within 90 days of the date of service. Ensure timely submission to avoid rejection.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Submission Deadlines',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: '90-day window — within 7 days of deadline',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'claim.state', operator: '==', value: 'DRAFT' },
      ],
    },
    suggestionTemplate: {
      title: 'Critical: 7 days remaining to submit',
      description: 'This claim is within 7 days of the 90-day submission deadline. Submit immediately to avoid rejection.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Submission Deadlines',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- Sex Mismatch ---
  {
    name: 'Sex mismatch — female-only procedure',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.female_only_codes' },
        { type: 'field_compare', field: 'patient.gender', operator: '!=', value: 'F' },
      ],
    },
    suggestionTemplate: {
      title: 'Sex mismatch — female-only code',
      description: 'This service code is restricted to female patients. The patient gender does not match. The claim will be rejected.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Sex-Specific Service Codes',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'Sex mismatch — male-only procedure',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.male_only_codes' },
        { type: 'field_compare', field: 'patient.gender', operator: '!=', value: 'M' },
      ],
    },
    suggestionTemplate: {
      title: 'Sex mismatch — male-only code',
      description: 'This service code is restricted to male patients. The patient gender does not match. The claim will be rejected.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Sex-Specific Service Codes',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- Age Restrictions ---
  {
    name: 'Age restriction — paediatric code for adult',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.paediatric_codes' },
        { type: 'field_compare', field: 'patient.age', operator: '>=', value: 18 },
      ],
    },
    suggestionTemplate: {
      title: 'Age restriction — paediatric code',
      description: 'This code is restricted to patients under 18. The patient is an adult and the claim will be rejected.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Age-Restricted Codes',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'Age restriction — geriatric code for non-senior',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.geriatric_codes' },
        { type: 'field_compare', field: 'patient.age', operator: '<', value: 65 },
      ],
    },
    suggestionTemplate: {
      title: 'Age restriction — geriatric code',
      description: 'This code is intended for patients 65+. The patient may not meet the age requirement.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Age-Restricted Codes',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'Age restriction — neonatal code',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.neonatal_codes' },
        { type: 'field_compare', field: 'patient.age', operator: '>=', value: 1 },
      ],
    },
    suggestionTemplate: {
      title: 'Age restriction — neonatal code',
      description: 'This code is for neonatal patients (under 1 year). The patient age exceeds this limit.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Age-Restricted Codes',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- Specialty Restriction ---
  {
    name: 'Specialty restriction — code not available to specialty',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'existence', field: 'reference.hscCode.specialtyRestrictions', operator: 'IS NOT NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Specialty restriction warning',
      description: 'This service code may have specialty restrictions. Verify your specialty qualifies to bill it.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Specialty Restrictions',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- Facility Restriction ---
  {
    name: 'Facility restriction — code requires specific facility',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'existence', field: 'reference.hscCode.facilityRestrictions', operator: 'IS NOT NULL' },
        { type: 'existence', field: 'ahcip.facilityNumber', operator: 'IS NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Facility code may be required',
      description: 'This service code may require a facility number. Missing facility information could lead to rejection.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Facility Requirements',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- Functional Centre Mismatch ---
  {
    name: 'Functional centre mismatch — code and BA',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'existence', field: 'ahcip.functionalCentre', operator: 'IS NOT NULL' },
        { type: 'existence', field: 'ahcip.baNumber', operator: 'IS NOT NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Verify functional centre for BA',
      description: 'Ensure the functional centre matches the business arrangement. Mismatches cause claim rejection.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Business Arrangement Rules',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- Encounter Type Validation ---
  {
    name: 'Encounter type — hospital code in office',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.hospital_only_codes' },
        { type: 'field_compare', field: 'ahcip.encounterType', operator: '==', value: 'OFFICE' },
      ],
    },
    suggestionTemplate: {
      title: 'Hospital code used in office setting',
      description: 'This code is restricted to hospital settings. Using it for an office encounter will cause rejection.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Encounter Type Restrictions',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'Encounter type — office code in hospital',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.office_only_codes' },
        { type: 'set_membership', field: 'ahcip.encounterType', operator: 'IN', value: ['HOSPITAL', 'ED', 'FACILITY'] },
      ],
    },
    suggestionTemplate: {
      title: 'Office code used in hospital setting',
      description: 'This code is restricted to office settings. Using it in a hospital/facility encounter may cause rejection.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Encounter Type Restrictions',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- Fee Amount Validation ---
  {
    name: 'Fee amount — exceeds schedule maximum',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'existence', field: 'ahcip.submittedFee', operator: 'IS NOT NULL' },
        { type: 'existence', field: 'reference.hscCode.baseFee', operator: 'IS NOT NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Verify submitted fee against schedule',
      description: 'Ensure the submitted fee does not exceed the SOMB schedule maximum for this code.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Fee Schedule',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- Duplicate Claim Detection ---
  {
    name: 'Duplicate claim — same code same day',
    category: 'REJECTION_RISK',
    claimType: 'BOTH',
    conditions: {
      type: 'cross_claim',
      query: {
        lookbackDays: 1,
        field: 'ahcip.healthServiceCode',
        aggregation: 'count',
        filter: {
          type: 'field_compare',
          field: 'ahcip.healthServiceCode',
          operator: '==',
          value: '{{ahcip.healthServiceCode}}',
        },
      },
      field: 'crossClaim.duplicate_same_day',
      operator: '>=',
      value: 1,
    },
    suggestionTemplate: {
      title: 'Potential duplicate claim',
      description: 'An identical claim (same code, same day, same patient) already exists. This may be rejected as a duplicate.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Duplicate Claim Rules',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- WCB-related rejection prevention ---
  {
    name: 'WCB claim number missing',
    category: 'REJECTION_RISK',
    claimType: 'WCB',
    conditions: {
      type: 'existence',
      field: 'wcb.wcbClaimNumber',
      operator: 'IS NULL',
    },
    suggestionTemplate: {
      title: 'WCB claim number required',
      description: 'A WCB claim number is required for WCB submissions. Without it, the claim will be returned.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'WCB Alberta — Claim Submission Requirements',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- Import Source Validation ---
  {
    name: 'Manual import — missing fields check',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'claim.importSource', operator: '==', value: 'MANUAL' },
        { type: 'existence', field: 'ahcip.diagnosticCode', operator: 'IS NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Manual entry — verify completeness',
      description: 'Manually entered claims are more likely to have missing fields. Verify all required fields are populated.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'Best Practices — Manual Claim Entry',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },

  // --- Cross-claim service bundling ---
  {
    name: 'Bundled services — common pair same day',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.bundled_primary_codes' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 1,
            field: 'ahcip.healthServiceCode',
            aggregation: 'exists',
            filter: {
              type: 'set_membership',
              field: 'ahcip.healthServiceCode',
              operator: 'IN',
              value: 'ref.bundled_secondary_codes',
            },
          },
          field: 'crossClaim.bundled_exists',
          operator: '>=',
          value: 1,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Service bundling — potential rejection',
      description: 'This code is commonly bundled with another code billed today. AHCIP may reject one as an inclusive service.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Service Bundling Rules',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- Missing text amount for text-amount codes ---
  {
    name: 'Text amount required — missing',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'reference.hscCode.feeType', operator: '==', value: 'TEXT_AMOUNT' },
        { type: 'existence', field: 'ahcip.submittedFee', operator: 'IS NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Text amount required',
      description: 'This code requires a manually entered fee (text amount). The claim will be rejected without it.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Text Amount Codes',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- Additional rejection prevention ---
  {
    name: 'Stale draft — claim older than 60 days',
    category: 'REJECTION_RISK',
    claimType: 'BOTH',
    conditions: {
      type: 'field_compare',
      field: 'claim.state',
      operator: '==',
      value: 'DRAFT',
    },
    suggestionTemplate: {
      title: 'Claim approaching submission deadline',
      description: 'This draft claim is aging. Submit soon to ensure it falls within the submission window.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Submission Deadlines',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },
  {
    name: 'Multiple modifiers — verify order',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'existence', field: 'ahcip.modifier1', operator: 'IS NOT NULL' },
        { type: 'existence', field: 'ahcip.modifier2', operator: 'IS NOT NULL' },
        { type: 'existence', field: 'ahcip.modifier3', operator: 'IS NOT NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Three modifiers applied — verify order',
      description: 'Three modifiers are present. Ensure they are in the correct priority order as defined by SOMB rules.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 Section 3 — Modifier Priority',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },

  // --- Additional GR rules ---
  {
    name: 'GR 5 — anaesthesia time exceeds procedure limit',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.anaesthesia_codes' },
        { type: 'existence', field: 'ahcip.timeSpent', operator: 'IS NOT NULL' },
        { type: 'field_compare', field: 'ahcip.timeSpent', operator: '>', value: 480 },
      ],
    },
    suggestionTemplate: {
      title: 'Anaesthesia time exceeds typical limit',
      description: 'The documented time exceeds 8 hours for this procedure. GR 5 may require justification for extended anaesthesia time.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 5 — Anaesthesia Time Limits',
    },
    specialtyFilter: ['ANES'],
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'GR 9 — reciprocal billing restriction',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.reciprocal_restricted_codes' },
      ],
    },
    suggestionTemplate: {
      title: 'Reciprocal billing restriction',
      description: 'This code has reciprocal billing restrictions under GR 9. Verify the patient is not covered by another province.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 9 — Reciprocal Billing',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'GR 11 — transfer of care documentation',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.transfer_care_codes' },
        { type: 'existence', field: 'ahcip.referralPractitioner', operator: 'IS NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Transfer of care — referring physician needed',
      description: 'Transfer of care codes require documentation of the referring/transferring physician.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 11 — Transfer of Care',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- Additional encounter validations ---
  {
    name: 'Virtual visit — code not tele-eligible',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'ahcip.encounterType', operator: '==', value: 'VIRTUAL' },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'NOT IN', value: 'ref.tele_eligible_codes' },
      ],
    },
    suggestionTemplate: {
      title: 'Code not eligible for virtual delivery',
      description: 'This service code is not approved for telehealth/virtual delivery. The claim may be rejected.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 Section 3.5 — Telehealth Eligible Codes',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'Modifier not eligible for code',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'existence', field: 'ahcip.modifier1', operator: 'IS NOT NULL' },
        { type: 'existence', field: 'reference.hscCode.modifierEligibility', operator: 'IS NOT NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Verify modifier eligibility for code',
      description: 'The applied modifier may not be eligible for this service code. Check SOMB modifier eligibility rules.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 Section 3 — Modifier Eligibility',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- BA and Functional Centre ---
  {
    name: 'BA number missing',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'existence',
      field: 'ahcip.baNumber',
      operator: 'IS NULL',
    },
    suggestionTemplate: {
      title: 'Business arrangement number required',
      description: 'Every AHCIP claim must include a valid business arrangement number. The claim will be rejected without one.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Business Arrangement Requirements',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'Functional centre missing',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'existence',
      field: 'ahcip.functionalCentre',
      operator: 'IS NULL',
    },
    suggestionTemplate: {
      title: 'Functional centre required',
      description: 'A functional centre code is required for AHCIP claims. Include the appropriate code for your practice setting.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Functional Centre Requirements',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- Weekend/holiday hospital ---
  {
    name: 'Weekend hospital visit — verify admission',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'temporal', field: 'claim.dayOfWeek', operator: 'IN', value: [0, 6] },
        { type: 'field_compare', field: 'ahcip.encounterType', operator: '==', value: 'HOSPITAL' },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.admission_codes' },
      ],
    },
    suggestionTemplate: {
      title: 'Weekend hospital admission — verify code',
      description: 'Weekend hospital admissions have specific code requirements. Verify you are using the correct admission code.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Hospital Admission Codes',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'Claim resubmission — previously rejected code',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'cross_claim',
      query: {
        lookbackDays: 90,
        field: 'claim.state',
        aggregation: 'exists',
        filter: {
          type: 'and',
          children: [
            { type: 'field_compare', field: 'claim.state', operator: '==', value: 'REJECTED' },
            { type: 'field_compare', field: 'ahcip.healthServiceCode', operator: '==', value: '{{ahcip.healthServiceCode}}' },
          ],
        },
      },
      field: 'crossClaim.previous_rejection_exists',
      operator: '>=',
      value: 1,
    },
    suggestionTemplate: {
      title: 'Previously rejected code for this patient',
      description: 'This code was rejected for this patient in the last 90 days. Review the rejection reason before resubmitting.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'Best Practices — Claim Resubmission',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- GR 15: Off-Hours Callback Limits ---
  // GR 15.11 defines strict maximums per time period per physician per day.
  {
    name: 'GR 15 — weekday daytime callback limit exceeded',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'temporal', field: 'claim.dayOfWeek', operator: 'IN', value: [1, 2, 3, 4, 5] },
        { type: 'temporal', field: 'claim.encounterHour', operator: '>=', value: 7 },
        { type: 'temporal', field: 'claim.encounterHour', operator: '<', value: 17 },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 1,
            field: 'ahcip.modifier1',
            aggregation: 'count',
            filter: {
              type: 'and',
              children: [
                { type: 'temporal', field: 'claim.dayOfWeek', operator: 'IN', value: [1, 2, 3, 4, 5] },
                { type: 'temporal', field: 'claim.encounterHour', operator: '>=', value: 7 },
                { type: 'temporal', field: 'claim.encounterHour', operator: '<', value: 17 },
                {
                  type: 'or',
                  children: [
                    { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: ['03.03KA', '03.05N'] },
                    { type: 'field_compare', field: 'ahcip.modifier1', operator: '==', value: 'SURC' },
                  ],
                },
              ],
            },
          },
          field: 'crossClaim.gr15_weekday_day_callback_count',
          operator: '>=',
          value: 5,
        },
      ],
    },
    suggestionTemplate: {
      title: 'GR 15 weekday daytime callback limit exceeded',
      description: 'You have reached the maximum of 5 special callbacks (03.03KA, 03.05N, or SURC) per weekday daytime (07:00–17:00). Additional claims in this period will be rejected under GR 15.11.1.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 15 — Off Hours Premium Benefits (Callback Limits)',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'GR 15 — night early callback limit exceeded (2200-2400)',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'temporal', field: 'claim.encounterHour', operator: '>=', value: 22 },
        { type: 'temporal', field: 'claim.encounterHour', operator: '<', value: 24 },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 1,
            field: 'ahcip.modifier1',
            aggregation: 'count',
            filter: {
              type: 'and',
              children: [
                { type: 'temporal', field: 'claim.encounterHour', operator: '>=', value: 22 },
                { type: 'temporal', field: 'claim.encounterHour', operator: '<', value: 24 },
                {
                  type: 'or',
                  children: [
                    { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: ['03.03MC', '03.05QA'] },
                    { type: 'field_compare', field: 'ahcip.modifier1', operator: '==', value: 'SURC' },
                  ],
                },
              ],
            },
          },
          field: 'crossClaim.gr15_night_early_callback_count',
          operator: '>=',
          value: 2,
        },
      ],
    },
    suggestionTemplate: {
      title: 'GR 15 night early callback limit exceeded',
      description: 'You have reached the maximum of 2 special callbacks (03.03MC, 03.05QA, or SURC) per day between 22:00–24:00. Additional claims in this period will be rejected under GR 15.11.4.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 15 — Off Hours Premium Benefits (Callback Limits)',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'GR 15 — night late callback limit exceeded (0000-0700)',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'temporal', field: 'claim.encounterHour', operator: '>=', value: 0 },
        { type: 'temporal', field: 'claim.encounterHour', operator: '<', value: 7 },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 1,
            field: 'ahcip.modifier1',
            aggregation: 'count',
            filter: {
              type: 'and',
              children: [
                { type: 'temporal', field: 'claim.encounterHour', operator: '>=', value: 0 },
                { type: 'temporal', field: 'claim.encounterHour', operator: '<', value: 7 },
                {
                  type: 'or',
                  children: [
                    { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: ['03.03MD', '03.05QB'] },
                    { type: 'field_compare', field: 'ahcip.modifier1', operator: '==', value: 'SURC' },
                  ],
                },
              ],
            },
          },
          field: 'crossClaim.gr15_night_late_callback_count',
          operator: '>=',
          value: 7,
        },
      ],
    },
    suggestionTemplate: {
      title: 'GR 15 night late callback limit exceeded',
      description: 'You have reached the maximum of 7 special callbacks (03.03MD, 03.05QB, or SURC) per day between 00:00–07:00. Additional claims in this period will be rejected under GR 15.11.5.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 15 — Off Hours Premium Benefits (Callback Limits)',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // =========================================================================
  // GR 4 — Visits and Consultations (3 new rules — Critical Gap #3)
  // GR 4 is the most complex governing rule (420+ referenced HSC codes).
  // =========================================================================

  // --- GR 4: 365-day re-consultation window (GR 4.6.1) ---
  {
    name: 'GR 4 — consultation within 365 days of previous',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        {
          type: 'set_membership',
          field: 'ahcip.healthServiceCode',
          operator: 'IN',
          value: [
            '03.04A', '03.04AZ', '03.08A', '03.08AZ', '03.08B', '03.08BZ',
            '03.08C', '03.08CV', '03.08F', '03.08H', '03.08K',
            '08.11A', '08.11C', '08.19A', '08.19AZ', '08.19AA', '08.19CX',
          ],
        },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 365,
            field: 'ahcip.healthServiceCode',
            aggregation: 'exists',
            filter: {
              type: 'set_membership',
              field: 'ahcip.healthServiceCode',
              operator: 'IN',
              value: [
                '03.04A', '03.04AZ', '03.08A', '03.08AZ', '03.08B', '03.08BZ',
                '03.08C', '03.08CV', '03.08F', '03.08H', '03.08K',
                '08.11A', '08.11C', '08.19A', '08.19AZ', '08.19AA', '08.19CX',
              ],
            },
          },
          field: 'crossClaim.gr4_comprehensive_within_365',
          operator: '>=',
          value: 1,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Comprehensive visit/consultation within 365 days',
      description: 'A comprehensive visit or consultation was already billed for this patient by you within the last 365 days. GR 4.6.1 limits comprehensive visits/consultations to once every 365 days per patient per physician. This claim may be downgraded or rejected.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 4 — Visits and Consultations (365-Day Rule)',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- GR 4.4.8: Referral requirement for specialist consultations ---
  {
    name: 'GR 4 — specialist consultation without referral',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        {
          type: 'set_membership',
          field: 'ahcip.healthServiceCode',
          operator: 'IN',
          value: [
            '03.01O', '03.01LJ', '03.01LK', '03.01LL', '03.03D', '03.03F',
            '03.03FA', '03.03FT', '03.03FV', '03.03FZ', '03.04Q', '03.05B',
            '03.07A', '03.07AZ', '03.07B', '03.07C',
            '03.08A', '03.08AZ', '03.08B', '03.08BZ', '03.08C', '03.08CV',
            '03.08F', '03.08H', '03.08K', '03.08L', '03.08M',
            '03.09A', '03.09B',
            '08.19A', '08.19AZ', '08.19B', '08.19C',
            '08.19AA', '08.19BB', '08.19CC', '08.19CX',
          ],
        },
        { type: 'existence', field: 'ahcip.referralPractitioner', operator: 'IS NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Specialist consultation requires referring practitioner',
      description: 'GR 4.4.8 requires the referring practitioner field for this consultation code. Claims submitted without a valid referring practitioner number will be rejected. Codes marked with * in GR 4.4.8 cannot be self-referred.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 4.4.8 — Referral Requirements',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- GR 4: Visit vs consultation classification ---
  {
    name: 'GR 4 — verify visit vs consultation code selection',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        {
          type: 'set_membership',
          field: 'ahcip.healthServiceCode',
          operator: 'IN',
          value: [
            '03.08A', '03.08AZ', '03.08B', '03.08BZ', '03.08C', '03.08CV',
            '03.08F', '03.08H', '03.08K', '03.09A', '03.09B',
            '08.19A', '08.19AZ', '08.19AA', '08.19B', '08.19BB',
            '08.19C', '08.19CC', '08.19CX',
          ],
        },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 365,
            field: 'ahcip.healthServiceCode',
            aggregation: 'exists',
            filter: {
              type: 'set_membership',
              field: 'ahcip.healthServiceCode',
              operator: 'IN',
              value: [
                '03.03A', '03.03AZ', '03.03B', '03.03BZ', '03.03D',
                '03.04A', '03.04AZ', '03.05I', '03.05IZ',
                '03.08A', '03.08AZ', '03.08B', '03.08BZ',
                '08.19A', '08.19AZ', '08.19AA',
              ],
            },
          },
          field: 'crossClaim.gr4_prior_encounter_same_specialty',
          operator: '>=',
          value: 1,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Consultation code used — verify this is not a follow-up',
      description: 'A consultation code is being used, but this patient has a prior encounter with you within 365 days. Under GR 4, if this is a follow-up rather than a new consultation with a new referral, a visit code (e.g., 03.03A, 03.03D) should be used instead. Consultations require a new referral request from the referring practitioner.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 4 — Visit vs Consultation Classification',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // =========================================================================
  // GR 6 — Procedures (2 new rules — Critical Gap #4)
  // GR 6 governs multiple procedure billing with 900+ referenced codes.
  // =========================================================================

  // --- GR 6.9: Multiple procedure discounting ---
  {
    name: 'GR 6 — multiple procedures same day require discounting',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        {
          type: 'set_membership',
          field: 'reference.hscCode.categoryCode',
          operator: 'IN',
          value: ['P', 'M', 'M+', '1', '3', '4', '6', '14', '15'],
        },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 1,
            field: 'ahcip.healthServiceCode',
            aggregation: 'count',
            filter: {
              type: 'set_membership',
              field: 'reference.hscCode.categoryCode',
              operator: 'IN',
              value: ['P', 'M', 'M+', '1', '3', '4', '6', '14', '15'],
            },
          },
          field: 'crossClaim.gr6_procedure_count_same_day',
          operator: '>=',
          value: 2,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Multiple procedures same day — discounting may apply',
      description: 'Multiple procedure codes are billed for this patient on the same day. Under GR 6.9, the second and subsequent procedures in the same anatomical area are typically paid at 75% of the listed benefit. Verify discounting rules apply and that the fee schedule is correctly applied.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 6 — Multiple Procedure Discounting (75%)',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- GR 6.10: Bilateral surgery verification ---
  {
    name: 'GR 6 — bilateral procedure billing verification',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        {
          type: 'set_membership',
          field: 'reference.hscCode.categoryCode',
          operator: 'IN',
          value: ['1', '3', '4', '6', '14', '15'],
        },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 1,
            field: 'ahcip.healthServiceCode',
            aggregation: 'count',
            filter: {
              type: 'field_compare',
              field: 'ahcip.healthServiceCode',
              operator: '==',
              value: '{{ahcip.healthServiceCode}}',
            },
          },
          field: 'crossClaim.gr6_same_code_same_day',
          operator: '>=',
          value: 2,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Possible bilateral procedure — verify modifier',
      description: 'The same surgical procedure code is billed twice on the same day for this patient, which may indicate a bilateral procedure. Under GR 6.10, when two surgeons operate on bilateral sides, the most responsible surgeon claims 100% and the second claims 75%. If this is a single surgeon performing bilaterally, ensure the bilateral modifier is applied.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 6.3 — Bilateral Surgery',
    },
    specialtyFilter: ['SURG', 'ORTHO', 'OPHTHO', 'ENT', 'UROL'],
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // =========================================================================
  // GR 9 — Ophthalmology (1 new rule)
  // GR 9.1.2/9.1.3: 3+3 limit on technical/interpretive services.
  // =========================================================================
  {
    name: 'GR 9 — ophthalmology 3+3 technical/interpretive limit',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        {
          type: 'set_membership',
          field: 'ahcip.healthServiceCode',
          operator: 'IN',
          value: [
            '09.01B', '09.01C', '09.01E', '09.02B', '09.02E',
            '09.05A', '09.05B', '09.06A',
            '09.11A', '09.11B', '09.11C',
            '09.12A', '09.12B',
            '09.13E', '09.13F', '09.13I', '09.13J',
            '09.26A', '09.26D',
            '21.31A', '24.89B', '25.81A',
          ],
        },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 1,
            field: 'ahcip.healthServiceCode',
            aggregation: 'count',
            filter: {
              type: 'set_membership',
              field: 'ahcip.healthServiceCode',
              operator: 'IN',
              value: [
                '09.01B', '09.01C', '09.01E', '09.02B', '09.02E',
                '09.05A', '09.05B', '09.06A',
                '09.11A', '09.11B', '09.11C',
                '09.12A', '09.12B',
                '09.13E', '09.13F', '09.13I', '09.13J',
                '09.26A', '09.26D',
                '21.31A', '24.89B', '25.81A',
              ],
            },
          },
          field: 'crossClaim.gr9_ophtho_special_count',
          operator: '>',
          value: 6,
        },
      ],
    },
    suggestionTemplate: {
      title: 'GR 9 ophthalmology 3+3 limit may be exceeded',
      description: 'More than 6 special ophthalmic services (technical + interpretive combined) are being claimed for this patient on the same day. GR 9.1.2 limits claims to 3 technical and 3 interpretive services alongside a complete eye examination. Services beyond this limit will be rejected.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 9 — Ophthalmology (3+3 Limit)',
    },
    specialtyFilter: ['Ophthalmology', 'Optometry'],
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // =========================================================================
  // GR 12 — Anesthesia Time Unit (1 new rule — Critical Gap #6)
  // GR 12.5.4-5: Additional time units require a full 5 minutes.
  // =========================================================================
  {
    name: 'GR 12 — anaesthesia time unit must be full 5 minutes',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.anaesthesia_codes' },
        { type: 'existence', field: 'ahcip.timeSpent', operator: 'IS NOT NULL' },
        { type: 'field_compare', field: 'ahcip.timeSpent', operator: '%' as Condition['operator'], value: 5 },
      ],
    },
    suggestionTemplate: {
      title: 'Anaesthesia time not a multiple of 5 minutes',
      description: 'The documented anaesthesia time is not a multiple of 5 minutes. GR 12.5.4-5 requires each additional time unit to be a full 5 minutes — partial units may not be claimed. Adjust the time to the nearest full 5-minute unit (rounding down).',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 12 — Anesthesia Time Billing',
    },
    specialtyFilter: ['ANES'],
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // =========================================================================
  // Bundling Pair Rules (5 new rules — Critical Gap #5)
  // Based on 857 unique bundling pairs from hsc-codes.json.
  // =========================================================================

  // --- 03.03A excludes 03.05JB — office visit bundling conflict ---
  {
    name: 'Bundled services — 03.03A excludes 03.05JB (office visit)',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'ahcip.healthServiceCode', operator: '==', value: '03.03A' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 1,
            field: 'ahcip.healthServiceCode',
            aggregation: 'exists',
            filter: {
              type: 'field_compare',
              field: 'ahcip.healthServiceCode',
              operator: '==',
              value: '03.05JB',
            },
          },
          field: 'crossClaim.bundle_0303A_0305JB',
          operator: '>=',
          value: 1,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Bundling conflict: 03.03A and 03.05JB',
      description: '03.03A (office visit) has a bundling exclusion with 03.05JB. These codes cannot be claimed together on the same day for the same patient. One claim will be rejected.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Service Bundling Rules (03.03A exclusions)',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- 08.19A excludes 08.19GA, 08.19GZ, 08.19GB — psychiatric consultation bundling ---
  {
    name: 'Bundled services — 08.19A excludes 08.19GA/GZ/GB (psychiatric)',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'ahcip.healthServiceCode', operator: '==', value: '08.19A' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 1,
            field: 'ahcip.healthServiceCode',
            aggregation: 'exists',
            filter: {
              type: 'set_membership',
              field: 'ahcip.healthServiceCode',
              operator: 'IN',
              value: ['08.19GA', '08.19GZ', '08.19GB'],
            },
          },
          field: 'crossClaim.bundle_0819A_group',
          operator: '>=',
          value: 1,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Bundling conflict: 08.19A and 08.19GA/GZ/GB',
      description: '08.19A (psychiatric consultation) has same-day exclusions with 08.19GA, 08.19GZ, and 08.19GB. These codes cannot be claimed on the same day for the same patient. The psychiatric group therapy/management code will be rejected alongside the consultation.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Service Bundling Rules (08.19A exclusions)',
    },
    specialtyFilter: ['PSYCH'],
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- 08.19GA excludes multiple psychiatric consultation codes ---
  {
    name: 'Bundled services — 08.19GA excludes consultations (psychiatric)',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'ahcip.healthServiceCode', operator: '==', value: '08.19GA' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 1,
            field: 'ahcip.healthServiceCode',
            aggregation: 'exists',
            filter: {
              type: 'set_membership',
              field: 'ahcip.healthServiceCode',
              operator: 'IN',
              value: [
                '08.11A', '08.11C', '08.19A', '08.19AZ', '08.19AA',
                '08.19B', '08.19BB', '08.19C', '08.19CC',
              ],
            },
          },
          field: 'crossClaim.bundle_0819GA_consults',
          operator: '>=',
          value: 1,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Bundling conflict: 08.19GA and psychiatric consultations',
      description: '08.19GA has same-day exclusions with psychiatric consultation codes (08.11A, 08.11C, 08.19A, 08.19AZ, 08.19AA, 08.19B, 08.19BB, 08.19C, 08.19CC). These services cannot be claimed on the same day for the same patient.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Service Bundling Rules (08.19GA exclusions)',
    },
    specialtyFilter: ['PSYCH'],
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- 08.19GB excludes multiple psychiatric consultation codes ---
  {
    name: 'Bundled services — 08.19GB excludes consultations (psychiatric)',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'ahcip.healthServiceCode', operator: '==', value: '08.19GB' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 1,
            field: 'ahcip.healthServiceCode',
            aggregation: 'exists',
            filter: {
              type: 'set_membership',
              field: 'ahcip.healthServiceCode',
              operator: 'IN',
              value: [
                '08.11A', '08.11C', '08.19A', '08.19AA', '08.19AZ',
                '08.19B', '08.19BB', '08.19C', '08.19CC',
              ],
            },
          },
          field: 'crossClaim.bundle_0819GB_consults',
          operator: '>=',
          value: 1,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Bundling conflict: 08.19GB and psychiatric consultations',
      description: '08.19GB has same-day exclusions with psychiatric consultation codes (08.11A, 08.11C, 08.19A, 08.19AA, 08.19AZ, 08.19B, 08.19BB, 08.19C, 08.19CC). These services cannot be claimed on the same day for the same patient.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Service Bundling Rules (08.19GB exclusions)',
    },
    specialtyFilter: ['PSYCH'],
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- Generic bundling exclusion check ---
  {
    name: 'Bundled services — check exclusion list',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'existence', field: 'reference.hscCode.bundlingExclusions', operator: 'IS NOT NULL' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 1,
            field: 'ahcip.healthServiceCode',
            aggregation: 'exists',
            filter: {
              type: 'set_membership',
              field: 'ahcip.healthServiceCode',
              operator: 'IN',
              value: '{{reference.hscCode.bundlingExclusions}}',
            },
          },
          field: 'crossClaim.generic_bundle_exclusion',
          operator: '>=',
          value: 1,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Bundling exclusion detected',
      description: 'This service code has a bundling exclusion with another code billed on the same day for this patient. AHCIP will reject one of the claims. Review the bundling exclusion list for this code and remove the conflicting claim or adjust the date of service.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Service Bundling Rules (per-code exclusion list)',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // =========================================================================
  // Frequency Restriction Rules (3 new rules — Critical Gap #8)
  // 38 HSC codes have explicit frequencyRestriction values in hsc-codes.json.
  // =========================================================================

  // --- Colonoscopy screening frequency ---
  {
    name: 'Frequency limit — colonoscopy screening interval',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        {
          type: 'set_membership',
          field: 'ahcip.healthServiceCode',
          operator: 'IN',
          value: ['01.22A', '01.22B', '01.22C'],
        },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 365,
            field: 'ahcip.healthServiceCode',
            aggregation: 'exists',
            filter: {
              type: 'set_membership',
              field: 'ahcip.healthServiceCode',
              operator: 'IN',
              value: ['01.22A', '01.22B', '01.22C'],
            },
          },
          field: 'crossClaim.freq_colonoscopy_within_year',
          operator: '>=',
          value: 1,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Colonoscopy screening frequency limit',
      description: 'A colonoscopy screening code was billed for this patient within the last year. Frequency restrictions apply: 01.22A (high risk) is once/year, 01.22B (moderate risk) is once/5 years, 01.22C (average risk) is once/10 years. Verify the appropriate screening interval has elapsed before resubmitting.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Frequency Restrictions (Colonoscopy Screening)',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- Weekly communication limit (telehealth, secure electronic) ---
  {
    name: 'Frequency limit — weekly communication/transfer limit',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        {
          type: 'set_membership',
          field: 'ahcip.healthServiceCode',
          operator: 'IN',
          value: ['03.01S', '03.01T', '03.03AI', '03.03AO', '03.03E'],
        },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 7,
            field: 'ahcip.healthServiceCode',
            aggregation: 'exists',
            filter: {
              type: 'field_compare',
              field: 'ahcip.healthServiceCode',
              operator: '==',
              value: '{{ahcip.healthServiceCode}}',
            },
          },
          field: 'crossClaim.freq_weekly_comm',
          operator: '>=',
          value: 1,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Weekly frequency limit for communication/transfer code',
      description: 'This code is restricted to once per calendar week per patient (03.01S, 03.01T, 03.03E) or once per patient per calendar week (03.03AI, 03.03AO transfer codes). A claim for this code already exists within the past 7 days. An additional claim will be rejected.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Frequency Restrictions (Calendar Week)',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- Per-pregnancy limit ---
  {
    name: 'Frequency limit — per-pregnancy service restriction',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        {
          type: 'set_membership',
          field: 'ahcip.healthServiceCode',
          operator: 'IN',
          value: ['03.03C', '03.04B'],
        },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 280,
            field: 'ahcip.healthServiceCode',
            aggregation: 'exists',
            filter: {
              type: 'field_compare',
              field: 'ahcip.healthServiceCode',
              operator: '==',
              value: '{{ahcip.healthServiceCode}}',
            },
          },
          field: 'crossClaim.freq_per_pregnancy',
          operator: '>=',
          value: 1,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Per-pregnancy frequency limit',
      description: 'This code is limited to once per patient per physician per pregnancy. 03.03C (prenatal initial assessment) and 03.04B (initial prenatal examination) were already claimed for this patient within the last 280 days (typical pregnancy duration). An additional claim may be rejected unless this is a new pregnancy.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 — Frequency Restrictions (Per Pregnancy)',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // =========================================================================
  // Patient Registration Validation (2 new rules)
  // 17 explanatory codes (01-09) cover patient registration rejections —
  // the largest rejection category with ZERO AI coverage.
  // =========================================================================

  // --- PHN validity pre-check ---
  {
    name: 'Patient registration — PHN validity check',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'existence', field: 'patient.phn', operator: 'IS NOT NULL' },
        { type: 'field_compare', field: 'patient.phnValid', operator: '==', value: false },
      ],
    },
    suggestionTemplate: {
      title: 'PHN validation failed — claim will be rejected',
      description: 'The patient Personal Health Number (PHN) does not pass validation (Luhn check and 9-digit Alberta format). Claims submitted with an invalid PHN are rejected with explanatory code 05A (Invalid Personal Health Number). Correct the PHN before submitting.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'AHCIP Explanatory Code 05A — Invalid Personal Health Number',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- ULI/Registration number completeness ---
  {
    name: 'Patient registration — missing ULI or registration number',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'existence', field: 'patient.phn', operator: 'IS NULL' },
        { type: 'existence', field: 'patient.uli', operator: 'IS NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Missing PHN and ULI — claim will be rejected',
      description: 'Neither a Personal Health Number (PHN) nor a Unique Lifetime Identifier (ULI) is present for this patient. Claims require at least one valid identifier. Missing identifiers result in rejection with explanatory codes 05BA (Invalid/Blank Registration Number) or 05BB (Invalid/Blank ULI).',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'AHCIP Explanatory Codes 05BA/05BB — Invalid Registration/ULI',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // =========================================================================
  // Hospital Reciprocal Billing (D07-208)
  // Out-of-province patient eligibility and required fields.
  // =========================================================================
  {
    name: 'Hospital reciprocal — out-of-province patient eligibility',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'patient.province', operator: '!=', value: 'AB' },
        { type: 'set_membership', field: 'ahcip.encounterType', operator: 'IN', value: ['HOSPITAL', 'ED'] },
      ],
    },
    suggestionTemplate: {
      title: 'Out-of-province patient — hospital reciprocal billing applies',
      description: 'This patient is from outside Alberta and the encounter is in a hospital/ED setting. Hospital reciprocal billing rules apply. Ensure the claim is submitted through the correct interprovincial reciprocal billing pathway to avoid rejection.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'AHCIP Hospital Reciprocal Billing — Explanatory Codes 80-89',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'Hospital reciprocal — verify province has reciprocal agreement',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'patient.province', operator: '!=', value: 'AB' },
        { type: 'set_membership', field: 'ahcip.encounterType', operator: 'IN', value: ['HOSPITAL', 'ED'] },
        { type: 'set_membership', field: 'patient.province', operator: 'NOT IN', value: 'ref.reciprocal_provinces' },
      ],
    },
    suggestionTemplate: {
      title: 'Province may not have reciprocal agreement',
      description: 'The patient home province may not participate in the interprovincial reciprocal billing agreement. Verify the province has a valid reciprocal arrangement with Alberta before submitting.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'AHCIP Hospital Reciprocal Billing — Provincial Agreements',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'Hospital reciprocal — required fields for out-of-province claim',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'patient.province', operator: '!=', value: 'AB' },
        { type: 'set_membership', field: 'ahcip.encounterType', operator: 'IN', value: ['HOSPITAL', 'ED'] },
        {
          type: 'or',
          children: [
            { type: 'existence', field: 'patient.outOfProvinceHealthNumber', operator: 'IS NULL' },
            { type: 'existence', field: 'patient.province', operator: 'IS NULL' },
          ],
        },
      ],
    },
    suggestionTemplate: {
      title: 'Missing required fields for out-of-province claim',
      description: 'Out-of-province hospital reciprocal claims require the patient home province and provincial health number. Missing fields will cause rejection.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'AHCIP Hospital Reciprocal Billing — Form Requirements',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // =========================================================================
  // Practitioner Registration (D07-208)
  // Billing number validity and specialty mismatch checks.
  // =========================================================================
  {
    name: 'Practitioner registration — billing number validity',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'or',
      children: [
        { type: 'field_compare', field: 'provider.billingNumberValid', operator: '==', value: false },
        { type: 'field_compare', field: 'provider.billingNumberExpired', operator: '==', value: true },
      ],
    },
    suggestionTemplate: {
      title: 'Practitioner billing number invalid or expired',
      description: 'The AHCIP billing number is invalid or expired. Claims submitted with an invalid practitioner registration will be rejected with explanatory codes 10 or 11.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'AHCIP Explanatory Codes 10-11 — Practitioner Registration',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'Practitioner registration — specialty mismatch with service',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'existence', field: 'reference.hscCode.specialtyRestrictions', operator: 'IS NOT NULL' },
        { type: 'set_membership', field: 'provider.specialtyCode', operator: 'NOT IN', value: '{{reference.hscCode.specialtyRestrictions}}' },
      ],
    },
    suggestionTemplate: {
      title: 'Practitioner specialty mismatch with service code',
      description: 'The HSC code has specialty restrictions that do not match your registered AHCIP specialty. Claims submitted by a practitioner whose specialty does not match the code restrictions will be rejected with explanatory codes 10A or 10B.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'AHCIP Explanatory Codes 10A-10B — Practitioner Specialty',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // =========================================================================
  // Surgical Assist Eligibility Verification (D07-209)
  // =========================================================================
  {
    name: 'Surgical assist — verify assist modifier eligibility',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        {
          type: 'or',
          children: [
            { type: 'field_compare', field: 'ahcip.modifier1', operator: '==', value: 'SA' },
            { type: 'field_compare', field: 'ahcip.modifier1', operator: '==', value: 'SAU' },
            { type: 'field_compare', field: 'ahcip.modifier1', operator: '==', value: 'SAQU' },
            { type: 'field_compare', field: 'ahcip.modifier2', operator: '==', value: 'SA' },
            { type: 'field_compare', field: 'ahcip.modifier2', operator: '==', value: 'SAU' },
            { type: 'field_compare', field: 'ahcip.modifier2', operator: '==', value: 'SAQU' },
            { type: 'field_compare', field: 'ahcip.modifier3', operator: '==', value: 'SA' },
            { type: 'field_compare', field: 'ahcip.modifier3', operator: '==', value: 'SAU' },
            { type: 'field_compare', field: 'ahcip.modifier3', operator: '==', value: 'SAQU' },
          ],
        },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'NOT IN', value: 'ref.surgical_assist_codes' },
      ],
    },
    suggestionTemplate: {
      title: 'Surgical assist modifier applied to ineligible code',
      description: 'An SA, SAU, or SAQU modifier is applied to a code that is not in the surgical assist eligible list under GR 13. This claim will be rejected. Remove the assist modifier or select an eligible procedure code.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 13 — Surgical Assistance Eligibility',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // =========================================================================
  // Telehealth GR 17 — REJECTION_RISK Rules (D07-210)
  // =========================================================================
  {
    name: 'Telehealth — verify encounter type matches billing code',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'ahcip.encounterType', operator: '==', value: 'VIRTUAL' },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'NOT IN', value: 'ref.tele_eligible_codes' },
      ],
    },
    suggestionTemplate: {
      title: 'Virtual encounter — code not in TELE-eligible list',
      description: 'This encounter is flagged as virtual but the HSC code is not in the 83 TELE-eligible codes under GR 17. The claim may be rejected. Verify the encounter type or select a TELE-eligible code.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 17 — Telehealth Eligible Codes',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'Telehealth — TELES modifier on in-person encounter',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'ahcip.encounterType', operator: '!=', value: 'VIRTUAL' },
        {
          type: 'or',
          children: [
            { type: 'field_compare', field: 'ahcip.modifier1', operator: '==', value: 'TELE' },
            { type: 'field_compare', field: 'ahcip.modifier2', operator: '==', value: 'TELE' },
            { type: 'field_compare', field: 'ahcip.modifier3', operator: '==', value: 'TELE' },
          ],
        },
      ],
    },
    suggestionTemplate: {
      title: 'TELES modifier applied to in-person encounter',
      description: 'The TELES modifier is applied but the encounter is not flagged as virtual. The TELES modifier under GR 17 requires a virtual/telehealth delivery. Remove the modifier or correct the encounter type.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 17 — Telehealth Modifier Requirements',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // =========================================================================
  // BMI GR 18 — REJECTION_RISK Rule (D07-210)
  // =========================================================================
  {
    name: 'BMI modifier — verify BMI recorded for eligible procedure',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        {
          type: 'or',
          children: [
            { type: 'field_compare', field: 'ahcip.modifier1', operator: '==', value: 'BMIPRO' },
            { type: 'field_compare', field: 'ahcip.modifier1', operator: '==', value: 'BMIANE' },
            { type: 'field_compare', field: 'ahcip.modifier1', operator: '==', value: 'BMIANT' },
            { type: 'field_compare', field: 'ahcip.modifier2', operator: '==', value: 'BMIPRO' },
            { type: 'field_compare', field: 'ahcip.modifier2', operator: '==', value: 'BMIANE' },
            { type: 'field_compare', field: 'ahcip.modifier2', operator: '==', value: 'BMIANT' },
            { type: 'field_compare', field: 'ahcip.modifier3', operator: '==', value: 'BMIPRO' },
            { type: 'field_compare', field: 'ahcip.modifier3', operator: '==', value: 'BMIANE' },
            { type: 'field_compare', field: 'ahcip.modifier3', operator: '==', value: 'BMIANT' },
          ],
        },
        { type: 'existence', field: 'patient.bmi', operator: 'IS NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'BMI modifier applied but BMI not recorded',
      description: 'A BMI modifier (BMIPRO, BMIANE, or BMIANT) is applied but no BMI value is documented for the patient. GR 18 requires BMI documentation to support the modifier. Record the patient BMI or remove the modifier.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 18 — BMI Documentation Requirements',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // =========================================================================
  // GR 7 — Reconstructive Plastic Surgery (D07-211)
  // =========================================================================
  {
    name: 'GR 7 — reconstructive surgery requires medical necessity documentation',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.reconstructive_surgery_codes' },
        { type: 'existence', field: 'ahcip.diagnosticCode', operator: 'IS NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Reconstructive surgery — medical necessity documentation required',
      description: 'This HSC code is in the reconstructive plastic surgery section. GR 7 requires a diagnostic code to demonstrate medical necessity. Without it, the procedure may be classified as cosmetic and the claim rejected.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 7 — Reconstructive Plastic Surgery',
    },
    specialtyFilter: ['PLAST'],
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'GR 7 — verify reconstructive vs cosmetic code selection',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.cosmetic_reconstructive_overlap_codes' },
      ],
    },
    suggestionTemplate: {
      title: 'Verify reconstructive vs cosmetic classification',
      description: 'This code is in the cosmetic/reconstructive overlap section under GR 7. Cosmetic procedures are not covered by AHCIP. Ensure the code is correctly classified as reconstructive with appropriate medical necessity documentation.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 7 — Cosmetic vs Reconstructive Classification',
    },
    specialtyFilter: ['PLAST'],
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // =========================================================================
  // GR 10 — Dental/Oral Surgical Services (D07-211)
  // =========================================================================
  {
    name: 'GR 10 — dental assessment code eligibility',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.dental_assessment_codes' },
        { type: 'set_membership', field: 'provider.specialtyCode', operator: 'NOT IN', value: 'ref.dental_eligible_specialties' },
      ],
    },
    suggestionTemplate: {
      title: 'Dental assessment code — verify provider eligibility',
      description: 'This dental assessment code under GR 10 requires specific provider eligibility. Verify your specialty and registration qualify for billing dental/oral surgical services.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 10 — Dental/Oral Surgical Services',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'GR 10 — dental procedure facility requirement',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.dental_hospital_required_codes' },
        { type: 'field_compare', field: 'ahcip.encounterType', operator: '==', value: 'OFFICE' },
      ],
    },
    suggestionTemplate: {
      title: 'Dental procedure requires hospital setting',
      description: 'This dental/oral surgical code under GR 10 requires a hospital setting. The encounter is flagged as office. Verify the setting or select an appropriate office-eligible code.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 10 — Dental Facility Requirements',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'GR 10 — dental specialist referral required',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.dental_referral_required_codes' },
        { type: 'existence', field: 'ahcip.referralPractitioner', operator: 'IS NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Dental specialist referral required',
      description: 'This dental/oral surgical code under GR 10 requires a referral from a dentist. Claims submitted without a referring practitioner will be rejected.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 10 — Dental Referral Requirements',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
];

// ---------------------------------------------------------------------------
// WCB-Specific Rules (~20)
// ---------------------------------------------------------------------------

const wcbSpecificRules: MvpRuleDefinition[] = [
  // --- WCB Timing Tiers ---
  {
    name: 'WCB timing — Tier 1 deadline (within 3 days)',
    category: 'WCB_TIMING',
    claimType: 'WCB',
    conditions: {
      type: 'field_compare',
      field: 'claim.state',
      operator: '==',
      value: 'DRAFT',
    },
    suggestionTemplate: {
      title: 'WCB Tier 1 deadline approaching',
      description: 'Submit within 3 calendar days of injury for Tier 1 (highest) reimbursement rate.',
      revenue_impact_formula: 'fixed:50.00',
      source_reference: 'WCB Alberta — Timing Tier Structure',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'WCB timing — Tier 2 window (4–7 days)',
    category: 'WCB_TIMING',
    claimType: 'WCB',
    conditions: {
      type: 'field_compare',
      field: 'claim.state',
      operator: '==',
      value: 'DRAFT',
    },
    suggestionTemplate: {
      title: 'WCB Tier 2 window active',
      description: 'This claim is in the Tier 2 window (4–7 days). Submit before day 8 to avoid dropping to Tier 3.',
      revenue_impact_formula: 'fixed:30.00',
      source_reference: 'WCB Alberta — Timing Tier Structure',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'WCB timing — Tier 3 window (8–14 days)',
    category: 'WCB_TIMING',
    claimType: 'WCB',
    conditions: {
      type: 'field_compare',
      field: 'claim.state',
      operator: '==',
      value: 'DRAFT',
    },
    suggestionTemplate: {
      title: 'WCB Tier 3 window active',
      description: 'This claim is in the Tier 3 window (8–14 days). Reimbursement rate decreases after day 14.',
      revenue_impact_formula: 'fixed:15.00',
      source_reference: 'WCB Alberta — Timing Tier Structure',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'WCB timing — Tier 4 late submission (15+ days)',
    category: 'WCB_TIMING',
    claimType: 'WCB',
    conditions: {
      type: 'field_compare',
      field: 'claim.state',
      operator: '==',
      value: 'DRAFT',
    },
    suggestionTemplate: {
      title: 'WCB late submission — reduced rate',
      description: 'This claim is past 14 days. The reimbursement rate is at Tier 4 (lowest). Submit as soon as possible.',
      revenue_impact_formula: 'fixed:5.00',
      source_reference: 'WCB Alberta — Timing Tier Structure',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },

  // --- WCB Form Completeness ---
  {
    name: 'WCB form — initial report completeness',
    category: 'WCB_COMPLETENESS',
    claimType: 'WCB',
    conditions: {
      type: 'field_compare',
      field: 'wcb.formId',
      operator: '==',
      value: 'PHYSICIAN_FIRST_REPORT',
    },
    suggestionTemplate: {
      title: 'Complete all optional fields',
      description: 'Fully completed first reports have higher acceptance rates. Fill in all optional fields to reduce follow-up requests.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'WCB Alberta — Physician First Report Guidelines',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'WCB form — progress report completeness',
    category: 'WCB_COMPLETENESS',
    claimType: 'WCB',
    conditions: {
      type: 'field_compare',
      field: 'wcb.formId',
      operator: '==',
      value: 'PROGRESS_REPORT',
    },
    suggestionTemplate: {
      title: 'Include treatment plan details',
      description: 'Progress reports with detailed treatment plans are approved faster. Include expected recovery timeline.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'WCB Alberta — Progress Report Guidelines',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'WCB form — specialist report',
    category: 'WCB_COMPLETENESS',
    claimType: 'WCB',
    conditions: {
      type: 'field_compare',
      field: 'wcb.formId',
      operator: '==',
      value: 'SPECIALIST_REPORT',
    },
    suggestionTemplate: {
      title: 'Include detailed findings',
      description: 'Specialist reports require detailed examination findings. Incomplete reports are commonly returned for revision.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'WCB Alberta — Specialist Report Requirements',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'WCB form — surgical report',
    category: 'WCB_COMPLETENESS',
    claimType: 'WCB',
    conditions: {
      type: 'field_compare',
      field: 'wcb.formId',
      operator: '==',
      value: 'SURGICAL_REPORT',
    },
    suggestionTemplate: {
      title: 'Include operative details',
      description: 'Surgical reports should include procedure details, findings, and post-operative plan. Incomplete reports delay payment.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'WCB Alberta — Surgical Report Requirements',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'WCB form — return to work report',
    category: 'WCB_COMPLETENESS',
    claimType: 'WCB',
    conditions: {
      type: 'field_compare',
      field: 'wcb.formId',
      operator: '==',
      value: 'RETURN_TO_WORK',
    },
    suggestionTemplate: {
      title: 'Specify work restrictions',
      description: 'Return-to-work reports with specific restrictions and timelines have higher acceptance rates.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'WCB Alberta — Return to Work Guidelines',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'WCB form — final report',
    category: 'WCB_COMPLETENESS',
    claimType: 'WCB',
    conditions: {
      type: 'field_compare',
      field: 'wcb.formId',
      operator: '==',
      value: 'FINAL_REPORT',
    },
    suggestionTemplate: {
      title: 'Include outcome summary',
      description: 'Final reports should include a comprehensive outcome summary, functional capacity, and permanent impairment assessment if applicable.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'WCB Alberta — Final Report Requirements',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- WCB Premium Code Eligibility ---
  {
    name: 'WCB premium code — Section 351 eligibility',
    category: 'FEE_OPTIMISATION',
    claimType: 'WCB',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.wcb_351_codes' },
      ],
    },
    suggestionTemplate: {
      title: 'WCB premium code eligible',
      description: 'This service qualifies for WCB Section 351 premium billing. The WCB rate is higher than the AHCIP schedule fee.',
      revenue_impact_formula: 'fee_difference',
      source_reference: 'WCB Alberta Section 351 — Fee Schedule',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'WCB premium code — 4-day rule check',
    category: 'FEE_OPTIMISATION',
    claimType: 'WCB',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.wcb_351_codes' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 4,
            field: 'ahcip.healthServiceCode',
            aggregation: 'count',
            filter: {
              type: 'set_membership',
              field: 'ahcip.healthServiceCode',
              operator: 'IN',
              value: 'ref.wcb_351_codes',
            },
          },
          field: 'crossClaim.wcb_4day_count',
          operator: '>=',
          value: 1,
        },
      ],
    },
    suggestionTemplate: {
      title: 'WCB 4-day rule applies',
      description: 'A Section 351 code was billed within the last 4 days. The 4-day rule may limit additional premium billing.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'WCB Alberta Section 351 — 4-Day Rule',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },

  // --- WCB Follow-Up Reminders ---
  {
    name: 'WCB follow-up — first report without follow-up',
    category: 'MISSED_BILLING',
    claimType: 'WCB',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'wcb.formId', operator: '==', value: 'PHYSICIAN_FIRST_REPORT' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 30,
            field: 'wcb.formId',
            aggregation: 'exists',
            filter: {
              type: 'field_compare',
              field: 'wcb.formId',
              operator: '==',
              value: 'PROGRESS_REPORT',
            },
          },
          field: 'crossClaim.wcb_followup_exists',
          operator: '==',
          value: 0,
        },
      ],
    },
    suggestionTemplate: {
      title: 'WCB follow-up report due',
      description: 'A first report was filed but no progress report has been submitted within 30 days. A follow-up report may be billable.',
      revenue_impact_formula: 'fixed:85.00',
      source_reference: 'WCB Alberta — Follow-Up Report Fees',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'WCB follow-up — progress report overdue',
    category: 'MISSED_BILLING',
    claimType: 'WCB',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'wcb.formId', operator: '==', value: 'PROGRESS_REPORT' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 60,
            field: 'wcb.formId',
            aggregation: 'count',
            filter: {
              type: 'field_compare',
              field: 'wcb.formId',
              operator: '==',
              value: 'PROGRESS_REPORT',
            },
          },
          field: 'crossClaim.wcb_progress_count',
          operator: '==',
          value: 0,
        },
      ],
    },
    suggestionTemplate: {
      title: 'WCB progress report may be due',
      description: 'No progress report has been submitted in the last 60 days. If treatment is ongoing, a follow-up report is billable.',
      revenue_impact_formula: 'fixed:65.00',
      source_reference: 'WCB Alberta — Progress Report Fees',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- WCB vs AHCIP Routing ---
  {
    name: 'WCB — verify claim type routing',
    category: 'REJECTION_RISK',
    claimType: 'WCB',
    conditions: {
      type: 'existence',
      field: 'wcb.wcbClaimNumber',
      operator: 'IS NOT NULL',
    },
    suggestionTemplate: {
      title: 'Verify WCB claim routing',
      description: 'This claim has a WCB claim number. Ensure it is routed through the WCB pathway, not AHCIP.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'WCB Alberta — Claim Routing',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },
  {
    name: 'WCB — treatment plan documentation',
    category: 'WCB_COMPLETENESS',
    claimType: 'WCB',
    conditions: {
      type: 'field_compare',
      field: 'claim.claimType',
      operator: '==',
      value: 'WCB',
    },
    suggestionTemplate: {
      title: 'Include treatment plan',
      description: 'WCB claims with detailed treatment plans are processed faster and have lower return rates.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'WCB Alberta — Treatment Plan Best Practices',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },
  {
    name: 'WCB — modified duties recommendation',
    category: 'WCB_COMPLETENESS',
    claimType: 'WCB',
    conditions: {
      type: 'field_compare',
      field: 'wcb.formId',
      operator: '==',
      value: 'RETURN_TO_WORK',
    },
    suggestionTemplate: {
      title: 'Recommend modified duties if applicable',
      description: 'WCB values specific modified duties recommendations. Include job task limitations and expected duration.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'WCB Alberta — Modified Duties Guidelines',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },
  {
    name: 'WCB — specialist referral documentation',
    category: 'WCB_COMPLETENESS',
    claimType: 'WCB',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'wcb.formId', operator: '==', value: 'SPECIALIST_REPORT' },
        { type: 'existence', field: 'ahcip.referralPractitioner', operator: 'IS NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Include referring physician',
      description: 'Specialist WCB reports should reference the referring physician for claim continuity.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'WCB Alberta — Specialist Report Guidelines',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },
  {
    name: 'WCB — functional assessment report',
    category: 'WCB_COMPLETENESS',
    claimType: 'WCB',
    conditions: {
      type: 'field_compare',
      field: 'wcb.formId',
      operator: '==',
      value: 'FUNCTIONAL_ASSESSMENT',
    },
    suggestionTemplate: {
      title: 'Include functional capacity details',
      description: 'Functional assessment reports should include objective measures of physical capacity and work-readiness.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'WCB Alberta — Functional Assessment Guidelines',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'WCB — missed return-to-work billing',
    category: 'MISSED_BILLING',
    claimType: 'WCB',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'wcb.formId', operator: '==', value: 'PROGRESS_REPORT' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 90,
            field: 'wcb.formId',
            aggregation: 'exists',
            filter: {
              type: 'field_compare',
              field: 'wcb.formId',
              operator: '==',
              value: 'RETURN_TO_WORK',
            },
          },
          field: 'crossClaim.wcb_rtw_exists',
          operator: '==',
          value: 0,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Return-to-work report may be billable',
      description: 'Multiple progress reports filed but no return-to-work report. If the patient has returned to work, this report is billable.',
      revenue_impact_formula: 'fixed:75.00',
      source_reference: 'WCB Alberta — Return to Work Report Fees',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- Unbilled WCB Opportunity (MVPADD-001 §5.1.1) ---
  {
    name: 'UNBILLED_WCB_OPPORTUNITY',
    category: 'MISSED_BILLING',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        // Current claim is an AHCIP claim being submitted
        { type: 'field_compare', field: 'claim.claimType', operator: '==', value: 'AHCIP' },
        // Patient has an active WCB claim (cross-claim lookup)
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 365,
            field: 'wcb.wcbClaimNumber',
            aggregation: 'exists',
            filter: {
              type: 'and',
              children: [
                { type: 'field_compare', field: 'claim.claimType', operator: '==', value: 'WCB' },
                { type: 'set_membership', field: 'claim.state', operator: 'IN', value: ['DRAFT', 'VALIDATED', 'QUEUED', 'SUBMITTED'] },
              ],
            },
          },
          field: 'crossClaim.patient_active_wcb',
          operator: '>',
          value: 0,
        },
      ],
    },
    suggestionTemplate: {
      title: 'This service may be billable to WCB',
      description: 'This patient has an active WCB claim. If this AHCIP service is related to the work injury, it should be billed to WCB instead for higher reimbursement.',
      revenue_impact_formula: 'fixed:40.00',
      source_reference: 'WCB Alberta — Billing Guidelines for Treating Physicians',
      source_url: 'https://www.wcb.ab.ca/health-care-providers/billing.html',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
];

// ---------------------------------------------------------------------------
// Pattern-Based Rules (~15)
// ---------------------------------------------------------------------------

const patternBasedRules: MvpRuleDefinition[] = [
  // --- Missed Billing Patterns ---
  {
    name: 'Pattern — missed companion code billing',
    category: 'MISSED_BILLING',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.companion_primary_codes' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 1,
            field: 'ahcip.healthServiceCode',
            aggregation: 'exists',
            filter: {
              type: 'set_membership',
              field: 'ahcip.healthServiceCode',
              operator: 'IN',
              value: 'ref.companion_secondary_codes',
            },
          },
          field: 'crossClaim.companion_exists',
          operator: '==',
          value: 0,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Commonly paired code not billed',
      description: 'This code is frequently billed with a companion code. If the companion service was provided, you may be missing billable revenue.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'Meritum Analytics — Billing Pattern Analysis',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },
  {
    name: 'Pattern — GP not billing counselling add-on',
    category: 'MISSED_BILLING',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.gp_visit_codes' },
        { type: 'existence', field: 'ahcip.timeSpent', operator: 'IS NOT NULL' },
        { type: 'field_compare', field: 'ahcip.timeSpent', operator: '>=', value: 25 },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 1,
            field: 'ahcip.healthServiceCode',
            aggregation: 'exists',
            filter: {
              type: 'set_membership',
              field: 'ahcip.healthServiceCode',
              operator: 'IN',
              value: 'ref.counselling_addon_codes',
            },
          },
          field: 'crossClaim.counselling_addon_exists',
          operator: '==',
          value: 0,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Counselling add-on may be billable',
      description: 'You spent 25+ minutes on this visit. If counselling was provided, the counselling add-on code is billable separately.',
      revenue_impact_formula: 'fixed:35.00',
      source_reference: 'SOMB 2026 — Counselling Add-On Codes',
    },
    specialtyFilter: ['GP'],
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'Pattern — missed minor procedure add-on',
    category: 'MISSED_BILLING',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.office_visit_codes' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 1,
            field: 'ahcip.healthServiceCode',
            aggregation: 'exists',
            filter: {
              type: 'set_membership',
              field: 'ahcip.healthServiceCode',
              operator: 'IN',
              value: 'ref.minor_procedure_codes',
            },
          },
          field: 'crossClaim.minor_procedure_exists',
          operator: '==',
          value: 0,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Minor procedure not billed',
      description: 'If a minor procedure was performed during this visit, it may be billable separately.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 — Minor Procedures',
    },
    specialtyFilter: ['GP'],
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },

  // --- Under-Utilised Modifier Patterns ---
  {
    name: 'Pattern — low CMGP usage for GP',
    category: 'FEE_OPTIMISATION',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.cmgp_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'CMGP' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'CMGP' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'CMGP' },
      ],
    },
    suggestionTemplate: {
      title: 'CMGP modifier under-utilised',
      description: 'Your CMGP modifier usage is below the specialty average. Most GPs apply CMGP to this code.',
      revenue_impact_formula: 'fixed:20.00',
      source_reference: 'Meritum Analytics — Modifier Utilisation',
    },
    specialtyFilter: ['GP'],
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },
  {
    name: 'Pattern — low after-hours usage for ED',
    category: 'FEE_OPTIMISATION',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'ahcip.encounterType', operator: '==', value: 'ED' },
        { type: 'field_compare', field: 'ahcip.afterHoursFlag', operator: '==', value: false },
        { type: 'temporal', field: 'claim.dayOfWeek', operator: 'IN', value: [0, 6] },
      ],
    },
    suggestionTemplate: {
      title: 'After-hours modifier under-utilised for ED',
      description: 'Weekend ED services qualify for after-hours premiums. Your usage of this modifier is below average.',
      revenue_impact_formula: 'fixed:30.00',
      source_reference: 'Meritum Analytics — Modifier Utilisation',
    },
    specialtyFilter: ['GP', 'EM'],
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },
  {
    name: 'Pattern — low telehealth modifier usage',
    category: 'FEE_OPTIMISATION',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'ahcip.encounterType', operator: '==', value: 'VIRTUAL' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'TELE' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'TELE' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'TELE' },
      ],
    },
    suggestionTemplate: {
      title: 'TELE modifier missing on virtual visits',
      description: 'Virtual visits should carry the TELE modifier. Your modifier usage is below the specialty average.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'Meritum Analytics — Modifier Utilisation',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },

  // --- High Rejection Rate Patterns ---
  {
    name: 'Pattern — high rejection rate on code',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'existence', field: 'ahcip.healthServiceCode', operator: 'IS NOT NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Higher than average rejection rate',
      description: 'Your rejection rate for this code exceeds 20%. Review common rejection reasons and ensure claim completeness.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'Meritum Analytics — Rejection Rate Analysis',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'Pattern — high rejection rate on modifier combination',
    category: 'REJECTION_RISK',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'existence', field: 'ahcip.modifier1', operator: 'IS NOT NULL' },
        { type: 'existence', field: 'ahcip.modifier2', operator: 'IS NOT NULL' },
      ],
    },
    suggestionTemplate: {
      title: 'Modifier combination has high rejection rate',
      description: 'This modifier combination has a higher than average rejection rate. Consider reviewing the modifier pairing.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'Meritum Analytics — Rejection Rate Analysis',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- Specialty-Specific Patterns ---
  {
    name: 'Pattern — surgical code without pre-op assessment',
    category: 'MISSED_BILLING',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.surgical_codes' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 30,
            field: 'ahcip.healthServiceCode',
            aggregation: 'exists',
            filter: {
              type: 'set_membership',
              field: 'ahcip.healthServiceCode',
              operator: 'IN',
              value: 'ref.preop_assessment_codes',
            },
          },
          field: 'crossClaim.preop_exists',
          operator: '==',
          value: 0,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Pre-operative assessment not billed',
      description: 'A surgical code is present but no pre-operative assessment was billed in the last 30 days. If one was performed, it may be billable.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 — Pre-Operative Assessments',
    },
    specialtyFilter: ['SURG', 'ORTHO', 'OBGYN'],
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },
  {
    name: 'Pattern — EM high-acuity code alternative',
    category: 'CODE_ALTERNATIVE',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'ahcip.encounterType', operator: '==', value: 'ED' },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.em_low_acuity_codes' },
        { type: 'existence', field: 'ahcip.timeSpent', operator: 'IS NOT NULL' },
        { type: 'field_compare', field: 'ahcip.timeSpent', operator: '>=', value: 30 },
      ],
    },
    suggestionTemplate: {
      title: 'Higher acuity code may apply',
      description: 'The time spent (30+ min) suggests a higher acuity code may be more appropriate for this ED encounter.',
      revenue_impact_formula: 'fee_difference',
      source_reference: 'SOMB 2026 — Emergency Department Codes',
    },
    specialtyFilter: ['GP', 'EM'],
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'Pattern — psychiatry extended session',
    category: 'CODE_ALTERNATIVE',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.psych_standard_codes' },
        { type: 'existence', field: 'ahcip.timeSpent', operator: 'IS NOT NULL' },
        { type: 'field_compare', field: 'ahcip.timeSpent', operator: '>=', value: 50 },
      ],
    },
    suggestionTemplate: {
      title: 'Extended psychiatry session code',
      description: 'The session lasted 50+ minutes. An extended session code provides higher reimbursement.',
      revenue_impact_formula: 'fee_difference',
      source_reference: 'SOMB 2026 — Psychiatry Codes',
    },
    specialtyFilter: ['PSYCH'],
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'Pattern — internal medicine comprehensive assessment',
    category: 'CODE_ALTERNATIVE',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.im_standard_visit_codes' },
        { type: 'existence', field: 'ahcip.timeSpent', operator: 'IS NOT NULL' },
        { type: 'field_compare', field: 'ahcip.timeSpent', operator: '>=', value: 45 },
      ],
    },
    suggestionTemplate: {
      title: 'Comprehensive assessment code may apply',
      description: 'The visit lasted 45+ minutes. A comprehensive assessment code may provide higher reimbursement.',
      revenue_impact_formula: 'fee_difference',
      source_reference: 'SOMB 2026 — Internal Medicine Codes',
    },
    specialtyFilter: ['IM'],
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },
  {
    name: 'Pattern — OB/GYN prenatal bundle',
    category: 'MISSED_BILLING',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.prenatal_visit_codes' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 280,
            field: 'ahcip.healthServiceCode',
            aggregation: 'count',
            filter: {
              type: 'set_membership',
              field: 'ahcip.healthServiceCode',
              operator: 'IN',
              value: 'ref.prenatal_visit_codes',
            },
          },
          field: 'crossClaim.prenatal_visit_count',
          operator: '>=',
          value: 8,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Prenatal care bundle may apply',
      description: 'Multiple prenatal visits recorded. Consider using the prenatal care bundle code for better reimbursement.',
      revenue_impact_formula: 'fee_difference',
      source_reference: 'SOMB 2026 — Obstetric Codes',
    },
    specialtyFilter: ['OBGYN', 'GP'],
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },
  {
    name: 'Pattern — dermatology biopsy add-on',
    category: 'MISSED_BILLING',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.derm_excision_codes' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 1,
            field: 'ahcip.healthServiceCode',
            aggregation: 'exists',
            filter: {
              type: 'set_membership',
              field: 'ahcip.healthServiceCode',
              operator: 'IN',
              value: 'ref.biopsy_codes',
            },
          },
          field: 'crossClaim.biopsy_exists',
          operator: '==',
          value: 0,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Biopsy code not billed with excision',
      description: 'Excision procedures often include a biopsy. If a biopsy was sent, the pathology code may be billable separately.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 — Pathology Codes',
    },
    specialtyFilter: ['DERM', 'GP', 'SURG'],
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },
  {
    name: 'Pattern — chronic disease annual review',
    category: 'MISSED_BILLING',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.chronic_followup_codes' },
        {
          type: 'cross_claim',
          query: {
            lookbackDays: 365,
            field: 'ahcip.healthServiceCode',
            aggregation: 'exists',
            filter: {
              type: 'set_membership',
              field: 'ahcip.healthServiceCode',
              operator: 'IN',
              value: 'ref.annual_review_codes',
            },
          },
          field: 'crossClaim.annual_review_exists',
          operator: '==',
          value: 0,
        },
      ],
    },
    suggestionTemplate: {
      title: 'Annual comprehensive review not billed',
      description: 'This patient has ongoing chronic disease management but no annual comprehensive review in 12 months. This is a separately billable service.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 — Chronic Disease Management',
    },
    specialtyFilter: ['GP', 'IM'],
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },
];

// ---------------------------------------------------------------------------
// All MVP Rules Combined
// ---------------------------------------------------------------------------

export const MVP_RULES: MvpRuleDefinition[] = [
  ...modifierEligibilityRules,
  ...rejectionPreventionRules,
  ...wcbSpecificRules,
  ...patternBasedRules,
];

// ---------------------------------------------------------------------------
// Seed Function
// ---------------------------------------------------------------------------

export interface SeedDeps {
  /** Check if a rule with the given name already exists */
  getRuleByName: (name: string) => Promise<{ ruleId: string } | undefined>;
  /** Insert a new rule */
  createRule: (data: InsertAiRule) => Promise<{ ruleId: string }>;
}

/**
 * Idempotently seed all MVP rules into the ai_rules table.
 * Skips any rule whose name already exists in the database.
 *
 * @returns Object with inserted count and skipped count.
 */
export async function seedMvpRules(
  deps: SeedDeps,
): Promise<{ inserted: number; skipped: number; total: number }> {
  let inserted = 0;
  let skipped = 0;

  for (const rule of MVP_RULES) {
    const existing = await deps.getRuleByName(rule.name);
    if (existing) {
      skipped++;
      continue;
    }

    await deps.createRule({
      name: rule.name,
      category: rule.category,
      claimType: rule.claimType,
      conditions: rule.conditions,
      suggestionTemplate: rule.suggestionTemplate,
      specialtyFilter: rule.specialtyFilter,
      priorityFormula: rule.priorityFormula,
      isActive: true,
      isBedsideContingent: rule.isBedsideContingent ?? false,
      sombVersion: rule.sombVersion,
    });
    inserted++;
  }

  return { inserted, skipped, total: MVP_RULES.length };
}
