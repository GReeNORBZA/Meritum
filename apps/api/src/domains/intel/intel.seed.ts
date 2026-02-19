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
}

// ---------------------------------------------------------------------------
// Modifier Eligibility Rules (~30)
// ---------------------------------------------------------------------------

const modifierEligibilityRules: MvpRuleDefinition[] = [
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

  // --- After-Hours (AFHR) Modifier Rules ---
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
      title: 'Consider after-hours modifier',
      description: 'This claim is from a weekday. If the service was provided after 17:00 or before 08:00, you may claim the after-hours premium.',
      revenue_impact_formula: 'fixed:30.00',
      source_reference: 'SOMB 2026 Section 2.3 — After-Hours Premium',
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
      title: 'Add after-hours modifier for weekend service',
      description: 'This service was on a weekend. Weekend services qualify for the after-hours premium.',
      revenue_impact_formula: 'fixed:30.00',
      source_reference: 'SOMB 2026 Section 2.3 — After-Hours Premium',
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
      title: 'Add after-hours modifier for statutory holiday',
      description: 'This service was on a statutory holiday. Statutory holidays qualify for the after-hours premium.',
      revenue_impact_formula: 'fixed:30.00',
      source_reference: 'SOMB 2026 Section 2.3 — After-Hours Premium',
      suggested_changes: [{ field: 'ahcip.afterHoursFlag', value_formula: 'true' }],
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

  // --- TELE (Telehealth) Modifier ---
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
      description: 'This virtual encounter is eligible for the TELE modifier. Adding it ensures proper categorisation.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 Section 3.5 — Telehealth',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'TELE' }],
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- BMI Modifier ---
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
      description: 'This service code is eligible for the BMI modifier if BMI was documented during the encounter.',
      revenue_impact_formula: 'fixed:5.00',
      source_reference: 'SOMB 2026 Section 3.2 — BMI Modifier',
      suggested_changes: [{ field: 'ahcip.modifier2', value_formula: 'BMI' }],
    },
    specialtyFilter: ['GP'],
    priorityFormula: 'fixed:LOW',
    sombVersion: '2026.1',
  },

  // --- COMP (Complexity) Modifier ---
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
      source_reference: 'SOMB 2026 Section 2.5 — Multiple Calls',
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
      source_reference: 'SOMB 2026 Section 10 — Anaesthesia',
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
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'ASST' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'ASST' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'ASST' },
      ],
    },
    suggestionTemplate: {
      title: 'Surgical assist modifier may apply',
      description: 'If you assisted on this surgical procedure, the ASST modifier enables claiming the surgical assist fee.',
      revenue_impact_formula: 'fee_lookup',
      source_reference: 'SOMB 2026 Section 9 — Surgical Procedures',
      suggested_changes: [{ field: 'ahcip.modifier1', value_formula: 'ASST' }],
    },
    specialtyFilter: ['SURG', 'ORTHO', 'OBGYN'],
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

  // --- NGHT (Night) Modifier ---
  {
    name: 'NGHT modifier — overnight service',
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
      title: 'Overnight premium may apply',
      description: 'If this hospital/ED service was between 22:00 and 07:00, the NGHT modifier premium applies.',
      revenue_impact_formula: 'fixed:35.00',
      source_reference: 'SOMB 2026 Section 2.4 — Night Premium',
      suggested_changes: [{ field: 'ahcip.afterHoursType', value_formula: 'NGHT' }],
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:MEDIUM',
    sombVersion: '2026.1',
  },

  // --- CMXP (Complex Paediatric) Modifier ---
  {
    name: 'CMXP modifier — complex paediatric visit',
    category: 'MODIFIER_ADD',
    claimType: 'AHCIP',
    conditions: {
      type: 'and',
      children: [
        { type: 'field_compare', field: 'patient.age', operator: '<', value: 18 },
        { type: 'set_membership', field: 'ahcip.healthServiceCode', operator: 'IN', value: 'ref.cmxp_eligible_codes' },
        { type: 'field_compare', field: 'ahcip.modifier1', operator: '!=', value: 'CMXP' },
        { type: 'field_compare', field: 'ahcip.modifier2', operator: '!=', value: 'CMXP' },
        { type: 'field_compare', field: 'ahcip.modifier3', operator: '!=', value: 'CMXP' },
      ],
    },
    suggestionTemplate: {
      title: 'Complex paediatric modifier may apply',
      description: 'This paediatric visit may qualify for the CMXP modifier if multiple conditions were managed.',
      revenue_impact_formula: 'fixed:18.00',
      source_reference: 'SOMB 2026 — Paediatric Modifiers',
      suggested_changes: [{ field: 'ahcip.modifier2', value_formula: 'CMXP' }],
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
];

// ---------------------------------------------------------------------------
// Rejection Prevention Rules (~40)
// ---------------------------------------------------------------------------

const rejectionPreventionRules: MvpRuleDefinition[] = [
  // --- GR 3: Visit Limits ---
  {
    name: 'GR 3 — daily visit limit same patient',
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
      title: 'GR 3 daily visit limit risk',
      description: 'You have already billed this code for this patient today. A duplicate may be rejected under GR 3.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 3 — Visit Frequency Limits',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'GR 3 — weekly visit limit same patient',
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
      title: 'GR 3 weekly visit limit risk',
      description: 'This patient has been billed this code 3+ times in 7 days. Additional claims may be rejected under GR 3.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 3 — Visit Frequency Limits',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'GR 3 — monthly visit limit same patient same code',
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
      title: 'GR 3 monthly frequency limit',
      description: 'This code has been billed 5+ times for this patient in the last 30 days. Consider an alternative code or documenting medical necessity.',
      revenue_impact_formula: 'fixed:0.00',
      source_reference: 'SOMB 2026 GR 3 — Visit Frequency Limits',
    },
    specialtyFilter: null,
    priorityFormula: 'fixed:HIGH',
    sombVersion: '2026.1',
  },
  {
    name: 'GR 3 — per-day max exceeded',
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
      source_reference: 'SOMB 2026 GR 3 — Visit Frequency Limits',
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
    name: 'Modifier conflict — CMGP and ASST',
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
              { type: 'field_compare', field: 'ahcip.modifier2', operator: '==', value: 'ASST' },
              { type: 'field_compare', field: 'ahcip.modifier3', operator: '==', value: 'ASST' },
            ]},
          ],
        },
        {
          type: 'and',
          children: [
            { type: 'field_compare', field: 'ahcip.modifier1', operator: '==', value: 'ASST' },
            { type: 'or', children: [
              { type: 'field_compare', field: 'ahcip.modifier2', operator: '==', value: 'CMGP' },
              { type: 'field_compare', field: 'ahcip.modifier3', operator: '==', value: 'CMGP' },
            ]},
          ],
        },
      ],
    },
    suggestionTemplate: {
      title: 'CMGP and ASST modifiers conflict',
      description: 'CMGP (primary care) and ASST (surgical assist) modifiers are mutually exclusive. Remove one.',
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
      sombVersion: rule.sombVersion,
    });
    inserted++;
  }

  return { inserted, skipped, total: MVP_RULES.length };
}
