# Meritum_Domain_07_Intelligence_Engine

MERITUM

Functional Requirements

Intelligence Engine

Domain 7 of 13  |  Critical Path: Position 7

Meritum Health Technologies Inc.

Version 2.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The Intelligence Engine is Meritum's AI Billing Coach. It analyses claims after the physician enters them and generates actionable suggestions to optimise billing accuracy and revenue. The engine operates as an advisory system — it never blocks submission and never modifies claims without the physician's explicit acceptance (except for Tier A auto-applied bedside-contingent rules, which the physician can review and reverse).

The core design principle is that physicians are already good at medicine; they are often not good at billing. The Intelligence Engine bridges this gap by applying billing expertise programmatically — catching missed modifiers, identifying code combination opportunities, flagging potential rejections before they happen, surfacing patterns the physician would not notice manually, and proactively alerting to unbilled revenue opportunities.

## 1.2 Three-Tier Processing Architecture

The Intelligence Engine uses a three-tier processing architecture that prioritises deterministic accuracy over AI novelty. Most suggestions come from Tier 1 (rules engine) with zero LLM cost. Tier 2 (LLM) handles nuanced cases. Tier 3 flags genuinely complex situations for human review.

| Tier | Engine | Cost | Use Case |
| --- | --- | --- | --- |
| Tier 1 | Deterministic Rules Engine | Zero marginal cost. Pure logic. | Modifier eligibility, code combinations, governing rule checks, missed billing patterns, revenue optimisation alerts. Handles ~80% of suggestions. |
| Tier 2 | Self-Hosted LLM | Low (self-hosted inference). No per-query API fees. | Natural-language explanations, nuanced clinical-billing mapping, complex modifier rationale. Handles ~15% of suggestions. |
| Tier 3 | Review Recommended | Zero. Flags for human review. | Genuinely ambiguous cases. Links to SOMB section, governing rule, or WCB policy. Handles ~5% of cases. |

## 1.3 Confidence-Tiered Application Model

In addition to the three processing tiers (which determine how suggestions are generated), the engine uses a confidence-tiered application model (which determines how suggestions are presented and applied to the physician). This model governs the interaction pattern between the suggestion and the physician.

| Confidence Tier | Label | Behaviour | Minimum Acceptance Rate |
| --- | --- | --- | --- |
| Tier A | Auto-apply | Rule automatically applied to the claim; physician not prompted. Used when contextual signals provide 100% deterministic confidence (e.g., after-hours modifier derived from shift encounter timestamps, weekend date-of-service). | 0.95 |
| Tier B | Pre-apply (opt-out) | Rule pre-applied to the claim; physician sees it as already applied and can remove it before save. Used when the physician's personal acceptance rate exceeds 80% for this rule. | 0.80 |
| Tier C | Suggestion (opt-in) | Shown as a standard suggestion card; physician must explicitly accept. Default tier for all rules without strong contextual signals or insufficient acceptance history. | 0.00 |
| Suppress | Suppressed | Rule hidden for this physician after repeated dismissals (consecutive_dismissals >= 5) or low acceptance rate (<30% over 10+ observations). Physician can manually re-enable. | N/A |

Confidence tier resolution is performed per rule per physician per claim. The resolution depends on two inputs: (1) bedside-contingent signals from the claim context, and (2) the physician's learning state for that rule.

## 1.4 Scope

Post-entry claim analysis: evaluate claims after physician saves, before submission

Suggestion generation: modifier recommendations, code alternatives, missed billing detection, rejection prevention

Revenue optimisation alerts: proactive detection of unbilled WCB opportunities, missing modifiers, and under-coded visits

Tier 1 rules engine: deterministic billing rules derived from SOMB, governing rules, and WCB policies

Tier 2 LLM integration: self-hosted model for natural-language explanations and nuanced analysis

Tier 3 review flagging: complex cases flagged with citations to authoritative sources

Confidence-tiered application: auto-apply (Tier A), pre-apply with undo (Tier B), suggestion-only (Tier C) based on contextual signals and physician learning state

Bedside-contingent rules: rules that fire based on shift encounter data and import source context

Learning loop: adapt suggestion priority, confidence tier, and relevance based on physician's specialty, patterns, and acceptance/dismissal history

Weekly digest: periodic summary of suggestion activity, acceptance rates, and estimated revenue impact per physician

Contextual help: tooltip content and inline guidance driven by Reference Data help_text fields

SOMB change impact analysis: when Reference Data is updated, assess impact on physician's typical billing patterns

Import-sourced claim evaluation: claims imported from Connect Care CSV, Connect Care SFTP, or ED Shift sources receive enhanced contextual signals for Tier A deterministic resolution

## 1.5 Out of Scope

Claim validation (Domain 4.0 validation engine — Intelligence Engine is advisory, not gating)

Claim modification (suggestions are proposals; the physician accepts or dismisses — except Tier A auto-apply which the physician can review and reverse)

Clinical decision support (Meritum is a billing platform, not clinical)

AI-driven customer support chatbot (Phase 1.5 — built on same LLM infrastructure but separate domain)

Automated coding from clinical notes (future enhancement; requires EMR integration)

## 1.6 Domain Dependencies

| Domain | Direction | Interface |
| --- | --- | --- |
| 2 Reference Data | Consumed | SOMB codes, governing rules, modifiers, code combinations, help_text, source references. The knowledge base for Tier 1 rules and Tier 3 citations. |
| 4.0 Claim Lifecycle Core | Consumed by | Claim context sent post-validation. Suggestions stored on claim's ai_coach_suggestions JSONB field. Import source field used for Tier A signal detection. |
| 4.1 AHCIP Pathway | Consumed by | AHCIP-specific suggestions: modifier eligibility, GR compliance, fee optimisation. |
| 4.2 WCB Pathway | Consumed by | WCB-specific suggestions: documentation completeness, timing tier awareness, form type guidance. |
| 5 Provider Management | Consumed | Physician specialty, practice locations, billing patterns for learning loop calibration. |
| 8 Analytics | Consumed by | Suggestion acceptance rates, revenue impact metrics, pattern data for learning loop. |
| 9 Notification Service | Consumed by | Weekly digest delivery via INTEL_WEEKLY_DIGEST notification event. SOMB change impact alerts via SOMB_CHANGE_IMPACT event. |
| 10 Mobile Companion v2 | Consumed | Shift encounter data as input to Tier A deterministic signals (AFHR/NGHT modifiers based on encounter timestamps). ED Shift import source context. |

# 2. Suggestion Model

## 2.1 Suggestion Structure

Each suggestion is a structured object stored in the claim's ai_coach_suggestions JSONB array (Domain 4.0, claims table).

| Field | Type | Description |
| --- | --- | --- |
| suggestion_id | UUID | Unique identifier for this suggestion instance |
| rule_id | UUID | FK to ai_rules. Empty string for Tier 2/3 suggestions not from rule library. |
| tier | INTEGER | 1, 2, or 3. Identifies which processing tier generated the suggestion. |
| category | VARCHAR(30) | Suggestion category (Section 2.2) |
| priority | VARCHAR(10) | HIGH, MEDIUM, LOW. Determines display order and visual emphasis. |
| title | VARCHAR(200) | Short actionable title shown in the suggestion card (e.g., 'Add CMGP modifier') |
| description | TEXT | Detailed explanation of why this suggestion applies and what the physician should do. |
| revenue_impact | DECIMAL(10,2) | Estimated fee difference if suggestion is accepted. Null if not calculable. Positive = more revenue. |
| confidence | DECIMAL(3,2) | 0.00–1.00. Tier 1 always 1.00 (deterministic). Tier 2 varies. Tier 3 always null (human review needed). |
| source_reference | VARCHAR(200) | Authoritative source: SOMB section, governing rule, WCB policy reference. Always populated. |
| source_url | VARCHAR(500) | Direct link to authoritative source document when available. |
| suggested_changes | JSONB | Array of `{field, value_formula}` change proposals. For one-click acceptance. Null for Tier 3. |
| status | VARCHAR(20) | PENDING, ACCEPTED, DISMISSED. Default: PENDING. |
| dismissed_reason | TEXT | Physician's optional reason for dismissal. Used in learning loop. |
| resolved_at | TIMESTAMPTZ | When the physician accepted or dismissed |
| resolved_by | UUID FK | Who resolved (physician or delegate with AI_COACH_MANAGE permission) |
| confidence_tier | VARCHAR(10) | Confidence application tier: TIER_A, TIER_B, TIER_C, or null for non-bedside rules |
| auto_applied | BOOLEAN | True when TIER_A auto-applied the suggestion without user interaction |
| pre_applied | BOOLEAN | True when TIER_B pre-applied the suggestion (user can opt-out) |

## 2.2 Suggestion Categories

| Category | Tier(s) | Description |
| --- | --- | --- |
| MODIFIER_ADD | 1, 2 | A modifier should be added. E.g., 'This visit qualifies for CMGP — did the encounter exceed 15 minutes?' |
| MODIFIER_REMOVE | 1 | A modifier is invalid or suboptimal. E.g., 'AFHR modifier not eligible for this HSC code.' |
| CODE_ALTERNATIVE | 1, 2 | A different HSC code may be more appropriate or pay better. E.g., 'Code X captures this encounter type at a higher rate.' |
| CODE_ADDITION | 1, 2 | An additional code could be billed for the same encounter. E.g., 'CMGP is billable alongside this visit code.' |
| MISSED_BILLING | 1, 2 | A billable service was likely performed but not claimed. Pattern-based detection across the physician's claim history. |
| REJECTION_RISK | 1 | The claim is likely to be rejected. E.g., 'GR 3 visit limit exceeded for this patient this month.' |
| DOCUMENTATION_GAP | 1 | Required documentation is missing for the billed code. E.g., 'Time-based code requires time_spent field.' |
| FEE_OPTIMISATION | 1, 2 | A different billing approach would yield more revenue. E.g., 'Unbundled billing for these services pays $X more than bundled.' |
| WCB_TIMING | 1 | WCB claim timing tier will downgrade if not submitted sooner. E.g., 'Submit by tomorrow 10:00 MT for same-day rate ($94.15 vs $85.80).' |
| WCB_COMPLETENESS | 1 | WCB form has fields that improve claim acceptance but are not strictly required. E.g., 'Adding objective findings strengthens this C050E.' |
| REVIEW_RECOMMENDED | 3 | Case is too complex for automated analysis. Links to relevant SOMB section or GR. E.g., 'GR 10(4)(b) may apply — review surgical coding rules.' |

## 2.3 Priority Assignment

Suggestion priority is determined by a combination of revenue impact and rejection risk:

HIGH: Revenue impact > $20.00 or rejection risk confidence > 0.80. Displayed prominently with attention indicator.

MEDIUM: Revenue impact $5.00–$20.00 or rejection risk 0.50–0.80. Standard display.

LOW: Revenue impact < $5.00, informational, or documentation suggestions. Collapsed by default, expandable.

Priority thresholds are configurable per physician specialty (radiologists have higher claim volumes with lower per-claim value; thresholds adjust accordingly).

Priority formulas on rules support two modes:
- `fixed:HIGH` / `fixed:MEDIUM` / `fixed:LOW` — fixed priority
- `revenue_based` — derived from revenue impact using threshold defaults

Revenue impact formulas on suggestion templates support:
- `fixed:XX.XX` — literal numeric value
- `fee_lookup` — look up base fee from Reference Data HSC code
- `fee_difference` — difference between reference fee and submitted fee

Priority adjustment from the learning loop (-1 demotes, 0 neutral, +1 promotes) shifts the effective priority but never promotes above the rule-defined maximum.

# 3. Tier 1: Deterministic Rules Engine

## 3.1 Architecture

The Tier 1 engine is a pure rules engine with zero LLM dependency. It evaluates claims against a library of billing rules derived from the SOMB schedule, governing rules, and WCB policies. Rules are expressed as condition→action pairs where conditions are evaluated against claim data and Reference Data, and actions generate suggestions.

This engine runs synchronously during the claim analysis request. Suggestions are available immediately after the physician requests analysis. There is no latency or cost associated with Tier 1 analysis.

The evaluation pipeline:

1. Build a pre-fetched claim context (ClaimContext) containing claim fields, anonymised patient demographics (age, gender — no PHN, no name), provider context (specialty, physician type, default location), AHCIP or WCB pathway fields, Reference Data lookups (HSC code, modifiers, diagnostic code), and pre-fetched cross-claim aggregates.

2. Fetch active rules matching the claim's type (AHCIP, WCB, or BOTH) and the provider's specialty code.

3. Batch-fetch learning states for the provider across all candidate rules.

4. Detect bedside-contingent signals from the claim context (import source, day of week, after-hours flag).

5. For each rule: check suppression → resolve confidence tier (for bedside-contingent rules) → evaluate condition tree → render suggestion from template → record GENERATED event → increment times_shown.

6. Deduplicate same-field suggestions (keep highest priority, then highest revenue impact).

7. Sort by priority (HIGH first), then revenue impact descending.

## 3.2 Claim Context

The claim context is a pre-fetched, anonymised data structure used for all rule evaluation. It is built once per analysis request and contains:

| Section | Contents |
| --- | --- |
| claim | claimId, claimType (AHCIP/WCB), state, dateOfService, dayOfWeek (0=Sun, 6=Sat), importSource (MANUAL, CONNECT_CARE_CSV, CONNECT_CARE_SFTP, ED_SHIFT) |
| ahcip | healthServiceCode, modifier1/2/3, diagnosticCode, functionalCentre, baNumber, encounterType, calls, timeSpent, facilityNumber, referralPractitioner, shadowBillingFlag, pcpcmBasketFlag, afterHoursFlag, afterHoursType, submittedFee |
| wcb | formId, wcbClaimNumber |
| patient | age (calculated from DOB and DOS), gender. No PHN, no name — anonymised to prevent PHI leakage. |
| provider | specialtyCode, physicianType (FFS/ARP), defaultLocation { functionalCentre, facilityNumber, rrnpEligible } |
| reference | hscCode (baseFee, feeType, specialtyRestrictions, facilityRestrictions, modifierEligibility, pcpcmBasket, maxPerDay, requiresReferral, surchargeEligible), modifiers (modifierCode, type, calculationMethod, combinableWith, exclusiveWith, requiresTimeDocumentation), diagnosticCode (diCode, qualifiesSurcharge, qualifiesBcp), sets (dynamic reference data sets for ref.{key} lookups) |
| crossClaim | Pre-fetched aggregate results keyed by query descriptor (e.g., count of same HSC code for same patient in last 30 days) |

## 3.3 Rule Condition Language

Rule conditions are evaluated against the claim context using a structured condition tree. The condition language supports:

Field comparison: `claim.healthServiceCode == '03.04A'`

Existence check: `ahcip.modifier1 IS NULL`

Set membership: `ahcip.healthServiceCode IN ref.cmgp_eligible_codes`

Temporal logic: `claim.dayOfWeek IN [0, 6]` (weekend), time range checks

Cross-claim queries: `COUNT(claims WHERE patient + same HSC + last 30 days) >= 5`

Nested conditions: AND, OR, NOT combinators with short-circuit evaluation

Reference set resolution: `ref.{key}` values are resolved from pre-fetched reference data sets in the claim context.

Conditions are parsed and evaluated by a lightweight expression evaluator operating on the pre-fetched context object. No SQL injection risk — all database queries are resolved during context building, before evaluation begins. Cross-claim aggregates are pre-fetched and deduplicated before any rule is evaluated.

## 3.4 Bedside-Contingent Rules

Bedside-contingent rules are rules that fire based on contextual signals derived from the claim's import source and temporal data, rather than relying solely on claim field values. These rules have `is_bedside_contingent = true` on the `ai_rules` table.

### 3.4.1 Tier A Signal Detection

Tier A signals indicate 100% deterministic confidence that a bedside-contingent rule applies. The following signals are detected from the claim context:

| Signal | Source | Description |
| --- | --- | --- |
| CONNECT_CARE_IMPORT | claim.importSource = 'CONNECT_CARE_CSV' or 'CONNECT_CARE_SFTP' | Claim imported from Connect Care structured data — encounter timestamps are reliable |
| ED_SHIFT_IMPORT | claim.importSource = 'ED_SHIFT' | Claim imported from ED shift data — encounter context is deterministic |
| DOS_WEEKEND | claim.dayOfWeek = 0 (Sunday) or 6 (Saturday) | Weekend date-of-service — after-hours premium applies automatically |
| AFTER_HOURS | ahcip.afterHoursFlag = true | After-hours flag already set from import context |

When any Tier A signal is present, bedside-contingent rules resolve to Tier A (auto-apply). The suggestion is applied without prompting the physician, and auto_applied_count is incremented on the learning state. Tier A auto-applications do not count as "shown" for acceptance rate calculations.

### 3.4.2 Confidence Tier Resolution

For bedside-contingent rules, confidence tier resolution follows this decision flow:

1. If any Tier A signal is present → **TIER_A** (auto-apply)
2. Else, check provider's learning state for this rule:
   - acceptance_rate > 0.70 AND times_shown >= 5 → **TIER_B** (pre-apply)
   - acceptance_rate < 0.30 AND times_shown >= 10 → **SUPPRESS**
   - Otherwise → **TIER_C** (standard suggestion)

Individual rules can override the default tier resolution via the `confidence_tier_overrides` JSONB field on the `ai_rules` table, enabling per-rule customisation of thresholds.

### 3.4.3 Tier B Removal Tracking

When a physician removes (opts out of) a Tier B pre-applied suggestion:

1. `pre_applied_removed_count` and `times_dismissed` are incremented.
2. Removal rate is calculated: `pre_applied_removed_count / pre_applied_count`.
3. After 10 pre-applied instances, if removal rate > 50%, the rule is demoted to Tier C via `priority_adjustment = -1`.

Tier B keeps (physician accepts the pre-applied suggestion) flow through the standard acceptance path, incrementing `times_accepted`.

## 3.5 MVP Rule Library

The initial Tier 1 rule library contains 105 deterministic rules targeting the highest-value suggestions for Meritum's primary user base (rural Alberta GPs). Rules are seeded idempotently via `intel.seed.ts` (skipping rules whose name already exists). The MVP rule categories:

### 3.5.1 Modifier Eligibility Rules (~30 rules)

CMGP eligibility: HSC code in CMGP-eligible list (office visit, comprehensive visit, chronic disease management, preventive care, mental health) AND no CMGP modifier present → suggest CMGP

After-hours eligibility: weekday evening, weekend, or statutory holiday AND no after-hours modifier → suggest AFHR/NGHT. Bedside-contingent: when import source provides deterministic timestamps, auto-applied as Tier A.

RRNP eligibility: provider location qualifies for rural/remote AND RRNP not applied → note RRNP premium (rural location, ED service variants)

Shadow billing: ARP physician AND no TM modifier → suggest TM (physician, specialist variants)

Time documentation: time-based HSC code AND time_spent missing or below threshold → flag documentation gap

Telehealth: virtual encounter AND no TELE modifier AND HSC eligible → suggest TELE

BMI: eligible code AND no BMI modifier → suggest BMI

Complexity: eligible code AND no COMP modifier → suggest COMP

PCPCM basket: HSC in PCPCM basket AND not flagged → suggest PCPCM routing

Multiple calls: single-call AND multi-call eligible code → suggest review

Facility surcharge: surcharge-eligible code at hospital/facility → suggest surcharge

Referral premium: consultation code with referring practitioner → suggest premium

Specialty-specific: anaesthesia time, surgical assist, ED surcharge, bilateral, LOCM, CALD, NGHT, CMXP (paediatric), URGN (urgent consultation)

### 3.5.2 Rejection Prevention Rules (~40 rules)

GR 3 visit limits: daily, weekly, monthly visit count limits AND per-day maximum via cross-claim queries → warn at HIGH priority

GR 8 referral required: specialist consultation without referring practitioner, specialist follow-up without initial referral in 365 days → error-level suggestion

Diagnostic code: required DI code missing → HIGH; recommended DI code missing → LOW

Modifier conflicts: generic mutually-exclusive pair detection, specific conflicts (TELE+EDSC, CMGP+ASST) → HIGH

90-day submission window: approaching deadline → MEDIUM; within 7 days → HIGH

Sex mismatch: female-only or male-only HSC code with mismatched patient gender → HIGH

Age restrictions: paediatric code for adult, adult code for paediatric → HIGH

Specialty restrictions: HSC code outside provider's specialty → HIGH

Facility restrictions: HSC code at wrong facility type → MEDIUM

### 3.5.3 WCB-Specific Rules (~20 rules)

Timing tier awareness: calculate current tier and fee, show deadline for next tier → urgency suggestion

Form completeness: optional fields that improve acceptance rates → completeness suggestion

Premium code eligibility: 351 premium applicable AND not claimed → suggest

Follow-up chain: parent claim exists but follow-up not yet created within expected window → remind

WCB claim number: missing claim number when previous WCB claims exist → suggest

Report completeness: report forms without required sections → flag

### 3.5.4 Pattern-Based Rules (~15 rules)

Missed billing patterns: physician consistently bills Code A but never Code B when Code B is commonly billed alongside → suggest review

Under-utilised modifiers: physician's modifier usage rate below specialty average → educational suggestion

High rejection codes: physician has >20% rejection rate on specific code → pre-emptive guidance

Under-coded visits: billing pattern suggests higher-value code may be appropriate based on encounter type and documentation level

Revenue gap detection: comparison of physician's billing patterns against specialty peers (requires minimum cohort size of 10)

# 4. Tier 2: LLM Integration

## 4.1 Architecture

Tier 2 uses a self-hosted open-source LLM deployed on Meritum infrastructure (DigitalOcean Toronto) accessed via the OpenAI-compatible `/v1/chat/completions` protocol. Compatible with llama.cpp, Ollama, vLLM, or any OpenAI-compatible API server. Self-hosting ensures zero per-query API fees, Canadian data residency for PHI-adjacent context, and no dependency on external AI providers.

The LLM client is configured via environment variables:
- `LLM_BASE_URL`: base URL for the OpenAI-compatible API
- `LLM_MODEL`: model identifier
- `LLM_API_KEY`: optional API key for authentication
- `LLM_TIMEOUT_MS`: latency budget override (default: 3000ms)

If `LLM_BASE_URL` or `LLM_MODEL` is not configured, Tier 2 is disabled and all analysis falls through to Tier 1 (deterministic) and Tier 3 (review recommended) with no degradation in safety-critical validation.

The LLM is not used for billing rule evaluation (that is Tier 1's job). It is used for:

Natural-language explanations: Translating deterministic rule outputs into physician-friendly explanations

Nuanced analysis: Cases where the billing rule is conditional on clinical context that Meritum cannot fully determine (e.g., 'If this was a comprehensive visit, CMGP applies')

Code alternative reasoning: Explaining why an alternative HSC code may be more appropriate, considering the clinical context described in claim fields

SOMB change summaries: Generating plain-language summaries of SOMB updates and their impact on the physician's billing

## 4.2 Prompt Architecture

The LLM receives a structured prompt containing:

System prompt: Billing domain expert instructions. Fixed per deployment. Includes constraints (never fabricate rules, always cite SOMB/GR sources, acknowledge uncertainty). Instructs the LLM to return structured JSON with defined fields.

Context block: Anonymised claim data (patient PHN and name stripped — replaced with placeholders), provider specialty, relevant SOMB rules from Reference Data, Tier 1 rule evaluation results.

Task instruction: Specific analysis request (e.g., 'Analyse this claim for additional billing optimisation opportunities not covered by the Tier 1 rules above. Focus on nuanced modifier applicability, code alternatives, and missed billing opportunities specific to the provider specialty and encounter context.').

The LLM never receives raw PHI (patient PHN, name). Claim context is anonymised via the `stripPhi` function which replaces referral practitioner IDs with 'PROVIDER_REF' and ensures no patient-identifying fields leak through. The LLM operates on billing structure (codes, modifiers, dates, clinical codes) not patient identity.

## 4.3 LLM Response Processing

Structured output: LLM is prompted to return JSON with defined fields (`explanation`, `confidence`, `source_reference`, `category`, `suggested_changes`, `revenue_impact`). Response format is enforced via `response_format: { type: 'json_object' }`. Free-text or malformed responses are discarded.

Confidence scoring: LLM self-reports confidence (0.00–1.00). Suggestions below 0.60 confidence are routed to Tier 3 (review recommended) rather than displayed as Tier 2 suggestions.

Hallucination guard: LLM output is validated against Reference Data via the `validateLlmSourceReference` function. Supported reference patterns:
- Governing Rule references (`GR1`, `GR-3`, `GR 12`) — looked up against active GOVERNING_RULES version
- Surcharge rule references (`SURCHARGE_1`) — looked up against active GOVERNING_RULES version
- HSC code references (`HSC:03.04A`) — looked up against active SOMB version
- SOMB section references (`SOMB ...`) — validated that SOMB data version exists
If the LLM cites a non-existent reference, the suggestion is suppressed and a SUPPRESSED event is logged with the hallucination details for rule library improvement.

Latency budget: Tier 2 analysis has a 3-second timeout (configurable via `LLM_TIMEOUT_MS`). If the LLM does not respond within the budget, the claim proceeds with Tier 1 suggestions only. Tier 2 results are delivered asynchronously and appended when available.

## 4.4 Asynchronous Delivery

Tier 2 runs as a fire-and-forget background task after Tier 1 results are returned to the caller:

1. Tier 1 suggestions are stored on the claim's `ai_coach_suggestions` JSONB and returned immediately.
2. Tier 2 is triggered in the background (not awaited).
3. On Tier 2 completion, new suggestions are appended to the claim's existing JSONB array.
4. WebSocket notification is broadcast on channel `intelligence:claim:{claimId}` with event `tier2_complete` containing the new suggestions.
5. On Tier 2 timeout or failure, no degradation occurs — Tier 1 results are already delivered.

## 4.5 Infrastructure

| Component | Specification |
| --- | --- |
| Model | Self-hosted open-source LLM. Model selection based on billing domain evaluation (accuracy on modifier/code suggestions). Initial candidate: DeepSeek-class 7B–13B parameter model. |
| Protocol | OpenAI-compatible `/v1/chat/completions`. Works with llama.cpp, Ollama, vLLM. |
| Hosting | DigitalOcean Toronto (same region as application). GPU droplet or inference-optimised instance. Canadian data residency maintained. |
| Scaling | Single instance sufficient for MVP (<100 physicians). Horizontal scaling via request queue if needed. |
| Cost model | Fixed infrastructure cost (~$200–$500/month for GPU instance). Zero per-query cost. Contrast with API-based models at $0.01–$0.10/query. |
| Fallback | If LLM instance is unavailable, all analysis falls through to Tier 1 (deterministic) and Tier 3 (review recommended). No degradation in safety-critical validation. |

# 5. Tier 3: Review Recommended

## 5.1 Purpose

Tier 3 is the honesty layer. When the system detects a billing situation it cannot resolve with confidence, it flags the case as 'Review recommended' and provides the physician with direct links to the relevant authoritative source. This avoids the failure mode of confident-but-wrong AI suggestions.

## 5.2 Triggers

Tier 2 low confidence: LLM returns confidence below 0.60 → escalate to Tier 3

Complex governing rules: GR with multiple interacting conditions that depend on clinical context Meritum cannot verify (e.g., GR 10 surgical coding with anaesthesia interaction)

Novel code combinations: Claim uses a code/modifier combination not seen in the physician's history or the specialty's typical patterns

Conflicting rules: Two governing rules produce contradictory guidance for the same claim

SOMB change impact: A recently changed rule affects a code the physician frequently uses, and the change is complex enough to warrant manual review

## 5.3 Review Suggestion Format

Tier 3 suggestions differ from Tier 1/2 in that they do not propose a specific change. Instead they provide:

Title: Trigger-specific title describing the area of concern. Supported triggers: `llm_low_confidence` ('automated analysis inconclusive'), `complex_gr_interaction` ('Complex governing rule interactions may affect…'), `novel_code_combination` ('Unusual code/modifier combination…'), `conflicting_rules` ('Conflicting rules detected…'), `somb_change_impact` ('Recent SOMB changes may affect…').

Description: Plain-language explanation of the ambiguity or complexity, referencing the specific HSC code.

Source reference: Specific SOMB section, governing rule number, or WCB policy clause.

Source URL: Direct link to the authoritative document (when available).

No suggested_changes: Field is null. No one-click acceptance. Physician must review and decide.

No revenue_impact: Field is null. Cannot be calculated for ambiguous cases.

Confidence: Explicitly null to signal human review is needed. (Exception: when escalated from Tier 2 low confidence, the LLM's confidence score is preserved for transparency.)

# 6. Revenue Optimisation Alerts

## 6.1 Purpose

Revenue optimisation alerts are proactive notifications generated by the Intelligence Engine to identify unbilled revenue opportunities. Unlike standard suggestions (which analyse claims the physician has already entered), revenue optimisation alerts detect situations where the physician may be leaving money on the table based on patterns in their claim history, patient encounters, and billing behaviour.

## 6.2 Alert Types

### 6.2.1 Unbilled WCB Opportunities

Detection: Patient has a workplace injury indicator or recent WCB claim history, but a recent AHCIP claim was submitted without a corresponding WCB claim.

Signal: Cross-claim query identifies patients with both AHCIP and WCB claim history where a recent AHCIP encounter may have been WCB-eligible.

Category: MISSED_BILLING

### 6.2.2 Missing Modifier Detection

Detection: Time-based modifiers (AFHR, NGHT) not applied despite eligible service time derived from shift encounter data or claim timestamps.

Signal: Bedside-contingent rules fire as Tier A (deterministic auto-apply) for after-hours and night premiums when import source provides reliable timestamps.

Category: MODIFIER_ADD

### 6.2.3 Under-Coded Visits

Detection: Billing pattern analysis suggests a higher-value HSC code may be appropriate based on encounter type, time documentation, and specialty norms.

Signal: Pattern-based rules compare the physician's code selection against specialty cohort averages.

Category: CODE_ALTERNATIVE or FEE_OPTIMISATION

## 6.3 Delivery

Revenue optimisation alerts are delivered through the same suggestion infrastructure as standard claim analysis. They appear in the claim's suggestion cards with appropriate priority and category labelling. Alerts generated from proactive pattern detection (not tied to a specific claim) are surfaced through the weekly digest and in-app notification system.

# 7. Learning Loop

## 7.1 Signals

The learning loop adapts the Intelligence Engine to each physician's billing patterns over time. It collects signals from:

Suggestion acceptance rate: Which categories and specific rules does this physician consistently accept? Increase priority.

Suggestion dismissal rate: Which suggestions does this physician consistently dismiss? Decrease priority or suppress after N consecutive dismissals.

Dismissal reasons: Free-text reasons provide qualitative signal. Common reasons may indicate a rule needs refinement.

Rejection history: Claims rejected by AHCIP/WCB after the physician dismissed a REJECTION_RISK suggestion → strong signal that the rule was correct.

Billing patterns: Frequency of code/modifier usage relative to specialty average. Unusual patterns trigger exploratory suggestions.

Specialty cohort: Aggregate acceptance/dismissal rates across all physicians of the same specialty. New physicians start with specialty defaults.

Auto-apply tracking: Tier A auto-applied count tracked separately. Auto-applications do not affect acceptance rate calculations.

Pre-apply tracking: Tier B pre-applied count and pre-applied removed count tracked to detect removal patterns.

## 7.2 Adaptation Mechanisms

| Mechanism | Behaviour |
| --- | --- |
| Priority adjustment | Calculated from acceptance rate after each accept/dismiss. Requires minimum 5 observations. acceptance_rate > 0.70 → +1 (promote). acceptance_rate < 0.30 → -1 (demote). Otherwise → 0. Priority never promoted above the rule-defined maximum. |
| Suppression threshold | After 5 consecutive dismissals of the same rule for the same physician, the rule is suppressed (not generated). Physician can re-enable suppressed rules in settings via the unsuppress endpoint. |
| Confidence tier promotion | For bedside-contingent rules: acceptance_rate > 0.70 with 5+ observations → promote to Tier B (pre-apply). Tier A is reserved for deterministic contextual signals only. |
| Tier B demotion | If Tier B removal rate > 50% over 10+ pre-applied instances → demote to Tier C (standard suggestion) via priority_adjustment = -1. |
| Specialty calibration | New physicians inherit the median acceptance rates from their specialty cohort. Personalisation develops over the first ~50 claims (CALIBRATION_CLAIMS = 50). |
| Rejection feedback | If a claim is rejected for a reason that a dismissed REJECTION_RISK suggestion predicted, the system re-enables the rule (unsuppresses if suppressed) and sets priority_adjustment = +1 permanently. A REJECTION_FEEDBACK event is logged. |
| Seasonal patterns | Some billing patterns are seasonal (flu season, allergy season). The learning loop uses rolling 90-day windows (ROLLING_WINDOW_DAYS = 90), not lifetime averages. |

## 7.3 Privacy Constraints

The learning loop operates on billing patterns (code frequencies, modifier usage, acceptance rates) not clinical data. No patient-identifying information enters the learning loop tables. Specialty cohort aggregation requires minimum 10 physicians per cohort (MIN_COHORT_SIZE = 10) before aggregate patterns are used — smaller cohorts risk de-identification.

# 8. Weekly Digest Service

## 8.1 Purpose

The digest service generates a weekly summary of AI Coach suggestion activity for each physician. It aggregates suggestion events over a billing period and produces a digest summary delivered via the notification system.

## 8.2 Digest Contents

Each per-physician digest contains:

| Field | Type | Description |
| --- | --- | --- |
| providerId | UUID | Physician identifier |
| periodStart | DATE | Start of the digest period (inclusive) |
| periodEnd | DATE | End of the digest period (exclusive) |
| totalGenerated | INTEGER | Number of suggestions generated during the period |
| totalAccepted | INTEGER | Number of suggestions accepted |
| totalDismissed | INTEGER | Number of suggestions dismissed |
| acceptanceRate | DECIMAL(5,4) | Acceptance rate for the period |
| estimatedRevenueImpact | DECIMAL(10,2) | Sum of revenue_impact for accepted suggestions |
| topCategories | JSONB | Top 5 categories by generated count, each with generated/accepted/dismissed counts and revenue impact |

## 8.3 Execution

The digest runs as a scheduled job (cron) with a default weekly period (last 7 days ending today). For each active provider with suggestion activity in the period:

1. Fetch suggestion events for the period from ai_suggestion_events.
2. Compute the digest summary (categorised by suggestion category).
3. Emit an `INTEL_WEEKLY_DIGEST` notification event via the notification service (Domain 9).
4. Log an audit event for the digest generation.

Providers with no activity during the period are skipped (no empty digests).

# 9. Data Model

Suggestions themselves are stored on the claim (Domain 4.0, claims.ai_coach_suggestions JSONB). This domain owns the rule library and the learning loop state.

## 9.1 Rules Table (ai_rules)

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| rule_id | UUID | No | Primary key (auto-generated) |
| name | VARCHAR(100) | No | Human-readable rule name (e.g., 'CMGP Modifier Eligibility') |
| category | VARCHAR(30) | No | Suggestion category (Section 2.2) |
| claim_type | VARCHAR(10) | No | AHCIP, WCB, or BOTH. Which pathway this rule applies to. |
| conditions | JSONB | No | Structured condition tree evaluated against claim context (Section 3.3) |
| suggestion_template | JSONB | No | Title, description (with {{placeholder}} tokens), revenue_impact_formula, source_reference, source_url, suggested_changes |
| specialty_filter | JSONB | Yes | Array of specialty codes this rule applies to. Null = all specialties. |
| priority_formula | VARCHAR(100) | No | Priority calculation expression (e.g., 'fixed:HIGH', 'revenue_based') |
| is_active | BOOLEAN | No | Active rules are evaluated. Inactive rules are skipped. Default: true. |
| is_bedside_contingent | BOOLEAN | No | True for rules that use confidence-tiered application model (Tier A/B/C). Default: false. |
| confidence_tier_overrides | JSONB | Yes | Per-rule override of confidence tier thresholds. Keys are signal names, values are tier identifiers. |
| somb_version | VARCHAR(20) | Yes | SOMB version this rule was derived from. For version-aware evaluation and change analysis. |
| created_at | TIMESTAMPTZ | No | Auto-generated |
| updated_at | TIMESTAMPTZ | No | Auto-updated on modification |

Indexes:
- `ai_rules_category_active_idx` on (category, is_active)
- `ai_rules_claim_type_active_idx` on (claim_type, is_active)
- `ai_rules_somb_version_idx` on (somb_version)

## 9.2 Provider Learning State Table (ai_provider_learning)

Per-physician learning state for each rule. Tracks acceptance/dismissal history, suppression, and confidence-tiered application metrics. Created lazily on first suggestion for this physician+rule pair.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| learning_id | UUID | No | Primary key (auto-generated) |
| provider_id | UUID FK | No | FK to providers |
| rule_id | UUID FK | No | FK to ai_rules |
| times_shown | INTEGER | No | Total times this rule generated a suggestion for this physician. Default: 0. |
| times_accepted | INTEGER | No | Times the physician accepted. Default: 0. |
| times_dismissed | INTEGER | No | Times dismissed. Default: 0. |
| consecutive_dismissals | INTEGER | No | Current streak of consecutive dismissals. Resets on acceptance. Default: 0. |
| auto_applied_count | INTEGER | No | Times this rule was auto-applied as Tier A (tracked for analytics; does not affect acceptance rate). Default: 0. |
| pre_applied_count | INTEGER | No | Times this rule was pre-applied as Tier B. Default: 0. |
| pre_applied_removed_count | INTEGER | No | Times the physician removed (opted out of) a Tier B pre-applied suggestion. Default: 0. |
| is_suppressed | BOOLEAN | No | True when consecutive_dismissals >= 5 or acceptance_rate < 0.30 over 10+ observations. Physician can manually un-suppress. Default: false. |
| priority_adjustment | INTEGER | No | Adjustment to base priority: -1 (demote), 0 (no change), +1 (promote). Derived from acceptance rate. Default: 0. |
| last_shown_at | TIMESTAMPTZ | Yes | When this rule last generated a suggestion for this physician |
| last_feedback_at | TIMESTAMPTZ | Yes | When the physician last accepted or dismissed |
| created_at | TIMESTAMPTZ | No | Auto-generated |
| updated_at | TIMESTAMPTZ | No | Auto-updated on modification |

Constraints: (provider_id, rule_id) unique.

Indexes:
- `ai_provider_learning_provider_rule_uniq` unique on (provider_id, rule_id)
- `ai_provider_learning_provider_suppressed_idx` on (provider_id, is_suppressed)
- `ai_provider_learning_rule_idx` on (rule_id)

## 9.3 Specialty Cohort Aggregates Table (ai_specialty_cohorts)

Aggregated acceptance/dismissal rates per specialty per rule. Updated nightly via scheduled recalculation job. Used to initialise new physicians.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| cohort_id | UUID | No | Primary key (auto-generated) |
| specialty_code | VARCHAR(10) | No | Specialty code |
| rule_id | UUID FK | No | FK to ai_rules |
| physician_count | INTEGER | No | Number of physicians contributing to this aggregate. Minimum 10 for use. |
| acceptance_rate | DECIMAL(5,4) | No | Aggregate acceptance rate (0.0000–1.0000) |
| median_revenue_impact | DECIMAL(10,2) | Yes | Median revenue impact when accepted |
| updated_at | TIMESTAMPTZ | No | Last recalculation timestamp |

Constraints: (specialty_code, rule_id) unique.

Indexes:
- `ai_specialty_cohorts_specialty_rule_uniq` unique on (specialty_code, rule_id)
- `ai_specialty_cohorts_specialty_idx` on (specialty_code)

## 9.4 Suggestion Audit Log (ai_suggestion_events)

Append-only log of all suggestion lifecycle events. Used for learning loop analysis, digest computation, and platform-wide metrics. No PHI stored — only billing metadata.

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| event_id | UUID | No | Primary key (auto-generated) |
| claim_id | UUID FK | No | FK to claims |
| suggestion_id | UUID | No | Suggestion ID from the claim's JSONB |
| rule_id | UUID FK | Yes | FK to ai_rules. Null for Tier 2/3 suggestions not from rule library. |
| provider_id | UUID FK | No | FK to providers |
| event_type | VARCHAR(20) | No | GENERATED, ACCEPTED, DISMISSED, SUPPRESSED, UNSUPPRESSED, REJECTION_FEEDBACK |
| tier | INTEGER | No | 1, 2, or 3 |
| category | VARCHAR(30) | No | Suggestion category |
| revenue_impact | DECIMAL(10,2) | Yes | Revenue impact at time of event |
| dismissed_reason | TEXT | Yes | For DISMISSED events: physician's reason. For SUPPRESSED events: hallucination guard details. |
| created_at | TIMESTAMPTZ | No | Auto-generated |

CRITICAL: Append-only. No UPDATE or DELETE operations exist. Same pattern as Domain 1 audit_log.

Indexes:
- `ai_suggestion_events_claim_idx` on (claim_id)
- `ai_suggestion_events_provider_created_idx` on (provider_id, created_at)
- `ai_suggestion_events_rule_event_idx` on (rule_id, event_type)
- `ai_suggestion_events_category_created_idx` on (category, created_at)

# 10. API Contracts

## 10.1 Suggestion Endpoints (Consumed by Domain 4)

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| POST | /api/v1/intelligence/analyse | AI_COACH_VIEW | Submit claim for analysis. Body: `{ claim_id: UUID, claim_context: {...} }`. Returns Tier 1 suggestions synchronously. Triggers Tier 2 analysis asynchronously (results delivered via WebSocket). |
| GET | /api/v1/intelligence/claims/:claim_id/suggestions | AI_COACH_VIEW | Get all suggestions for a claim. Returns from claim's JSONB (fast read). |
| POST | /api/v1/intelligence/suggestions/:id/accept | AI_COACH_MANAGE | Accept a suggestion. Applies suggested_changes to the claim (Domain 4 processes the change). Updates learning state. Triggers claim revalidation. |
| POST | /api/v1/intelligence/suggestions/:id/dismiss | AI_COACH_MANAGE | Dismiss a suggestion. Body: `{ reason?: string }`. Updates learning state and consecutive_dismissals. Checks suppression threshold. |

## 10.2 Learning & Preferences (Physician-facing)

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| GET | /api/v1/intelligence/me/learning-state | AI_COACH_VIEW | Get physician's learning state summary: suppressed rules count, top 3 accepted categories, total suggestions shown, overall acceptance rate. |
| POST | /api/v1/intelligence/me/rules/:rule_id/unsuppress | AI_COACH_MANAGE | Manually un-suppress a rule that was auto-suppressed after consecutive dismissals. Resets consecutive_dismissals to 0. |
| PUT | /api/v1/intelligence/me/preferences | AI_COACH_MANAGE | Set AI Coach preferences: enabled/disabled categories, priority thresholds (high_revenue, medium_revenue amounts). |

## 10.3 Rule Management (Admin Only)

| Method | Endpoint | Guard | Description |
| --- | --- | --- | --- |
| GET | /api/v1/intelligence/rules | AI_COACH_VIEW (all); admin sees full data, physicians see name+category+description only | List all rules with pagination and filters (category, claim_type, is_active). |
| POST | /api/v1/intelligence/rules | Admin | Create a new rule. New rules start inactive (is_active = false). |
| PUT | /api/v1/intelligence/rules/:id | Admin | Update a rule (conditions, template, specialty filter, etc.). |
| PUT | /api/v1/intelligence/rules/:id/activate | Admin | Toggle a rule's active state. Body: `{ is_active: boolean }`. |
| GET | /api/v1/intelligence/rules/:id/stats | Admin | Get rule performance: total_shown, total_accepted, total_dismissed, acceptance_rate, suppression_count across all physicians. |
| POST | /api/v1/intelligence/cohorts/recalculate | Admin | Trigger specialty cohort recalculation (normally nightly). Returns recalculated cohorts and count of deleted below-minimum cohorts. |

## 10.4 SOMB Change Analysis (Admin Only)

| Method | Endpoint | Guard | Description |
| --- | --- | --- | --- |
| POST | /api/v1/intelligence/somb-change-analysis | Admin | Given old and new SOMB versions, generate per-physician impact analysis. Returns affected rules (updated/deprecated/new), affected codes, estimated revenue impact, and plain-language summary per physician. Emits SOMB_CHANGE_IMPACT notification per affected physician. |

## 10.5 WebSocket (Real-time Tier 2 Delivery)

| Endpoint | Auth | Description |
| --- | --- | --- |
| GET /api/v1/intelligence/ws | Session cookie or query token | WebSocket connection for real-time Tier 2 result delivery. Client sends `{ type: 'subscribe', claimId: UUID }` to subscribe to a claim's analysis channel. Server broadcasts `{ event: 'tier2_complete', claimId, payload: { suggestions } }` when Tier 2 completes. |

Authentication: Session token extracted from cookie or query parameter, validated via session hash lookup. Invalid/expired sessions receive close code 4001.

# 11. Contextual Help System

The contextual help system provides in-app education at every point where billing complexity surfaces. It is driven by Reference Data help_text fields and is distinct from the AI Coach suggestions (which are claim-specific recommendations).

## 11.1 Help Content Types

| Type | Description |
| --- | --- |
| Field tooltips | Plain-language explanation of every billing field. E.g., hovering over 'CMGP' shows: 'Comprehensive modifier for encounters over 15 minutes. Applies to qualifying office visit codes.' |
| Validation warning help | When a validation warning fires, inline help explains the rule and suggests corrective action. Driven by Reference Data rule help_text. |
| Governing rule summaries | Expandable cards showing the governing rule in plain language with link to official SOMB source. Available on any code where GR applies. |
| WCB form guidance | Per-field guidance on WCB forms explaining what WCB expects. E.g., 'Objective findings: describe what you observed, not what the patient reports.' |
| SOMB change alerts | When a code or rule the physician frequently uses has changed, an in-app alert explains the change in plain language. |

## 11.2 Help Content Source

Help content is authored in Reference Data (Domain 2) as part of the code/rule/modifier records. Each Reference Data entity has a help_text field (plain language), a source_reference field (SOMB section or GR number), and an optional source_url field (link to official document). The Intelligence Engine does not generate help content — it consumes it from Reference Data and surfaces it in the UI context.

# 12. Analysis Orchestration

## 12.1 Initial Analysis (analyseClaim)

The full analysis pipeline for a claim:

1. **Tier 1 (synchronous):** Evaluate all applicable deterministic rules against the claim context. Generate Suggestion array. For bedside-contingent rules, resolve confidence tier and tag suggestions with auto_applied or pre_applied flags.
2. **Store:** Write Tier 1 results to the claim's ai_coach_suggestions JSONB. All suggestions marked PENDING.
3. **Return:** Return Tier 1 results to the caller immediately.
4. **Tier 2 (async):** If LLM is configured, trigger background analysis. On completion, append Tier 2 suggestions to the claim's JSONB and broadcast via WebSocket. On timeout or failure, no degradation.
5. **Audit:** Log CLAIM_ANALYSED event with tier1Count, tier2Triggered, tier3Count.

## 12.2 Re-analysis (reanalyseClaim)

When a claim is modified after initial analysis:

1. **Partition:** Get existing suggestions. Preserve ACCEPTED and DISMISSED suggestions. Clear PENDING suggestions.
2. **Re-evaluate:** Run Tier 1 evaluation on the updated claim context.
3. **Merge:** Combine preserved suggestions with new Tier 1 results. Store merged array.
4. **Tier 2:** Trigger background re-analysis if LLM is configured.
5. **Audit:** Log CLAIM_ANALYSED event with isReanalysis=true, preservedCount.

# 13. Security

PHI isolation from LLM: Patient-identifying information (PHN, name) is stripped from claim context before Tier 2 LLM analysis via the `stripPhi` function. The LLM receives billing structure (codes, modifiers, dates, clinical codes, provider specialty) but never patient identity. Referral practitioner IDs are replaced with 'PROVIDER_REF'.

Self-hosted LLM: No data leaves Meritum infrastructure. No external API calls for AI analysis. Canadian data residency maintained. LLM base URL configured via environment variable, not stored in database.

Learning data is billing patterns: Acceptance rates, code frequencies, modifier usage. No PHI enters the learning loop tables.

Specialty cohort privacy: Minimum 10 physicians per cohort before aggregates are computed. Prevents de-identification of small specialty groups. Cohorts with fewer than 10 physicians are deleted during nightly recalculation.

Rule library access: Rules viewable by physicians (name, category, description — transparency). Full rule data (conditions, templates) restricted to admin role. Rule creation/modification is admin-only with audit logging.

Suggestion audit log: All suggestion lifecycle events logged in append-only ai_suggestion_events table. Supports investigation of AI Coach accuracy and physician satisfaction. No UPDATE or DELETE operations exist on this table.

Physician scoping: Suggestion accept/dismiss operations resolve the physician's provider ID from the authenticated session context, never from request parameters. Cross-tenant access is prevented at the handler layer.

Permission guards: All endpoints require authentication. Physician-facing endpoints require AI_COACH_VIEW or AI_COACH_MANAGE permission. Admin endpoints require the ADMIN role. WebSocket connections require valid session token.

# 14. Testing Requirements

## 14.1 Tier 1 Tests

Each MVP rule (~105 rules) tested with positive and negative claim context:

CMGP suggestion: eligible claim without CMGP → suggestion generated. Claim with CMGP → no suggestion.

After-hours: weekday evening, weekend, statutory holiday variants. Bedside-contingent: verify Tier A auto-apply when import source is CONNECT_CARE_CSV or ED_SHIFT.

GR 3 rejection risk: visit limit exceeded via cross-claim query → HIGH priority rejection warning.

WCB timing: claim approaching tier downgrade → timing suggestion with correct fee values.

Specialty filter: rule with specialty_filter = ['GP'] does not fire for specialist claims.

Multiple rules on same claim: correct prioritisation, deduplication of same-field suggestions (keep highest priority).

Suppressed rule: rule with is_suppressed = true for this physician → not generated.

Bedside-contingent tier resolution: Tier A signals → auto_applied = true. No signals + high acceptance → TIER_B. Default → TIER_C. Low acceptance over 10+ → SUPPRESS.

## 14.2 Tier 2 Tests

LLM responds within 3-second timeout → suggestion appended to claim.

LLM timeout → Tier 1 suggestions unaffected, Tier 2 delivered asynchronously when available.

LLM confidence < 0.60 → escalated to Tier 3, not shown as Tier 2.

LLM cites non-existent SOMB section → suggestion suppressed, hallucination logged with SUPPRESSED event.

PHI stripping: verify patient PHN and name are replaced with placeholders in LLM prompt. Referral practitioner replaced with 'PROVIDER_REF'.

LLM instance down (base URL not configured) → getLlmClient returns null, graceful fallback to Tier 1 + Tier 3 only.

Hallucination guard: GR reference validated against active GOVERNING_RULES version. HSC reference validated against active SOMB version.

## 14.3 Learning Loop Tests

Accept suggestion → times_accepted increments, consecutive_dismissals resets to 0, is_suppressed set to false.

Dismiss suggestion 5 times consecutively → rule suppressed for that physician (is_suppressed = true).

Suppressed rule → no longer generates suggestions for that physician.

Un-suppress rule → rule resumes generating suggestions, consecutive_dismissals resets to 0.

Rejection feedback: dismissed REJECTION_RISK suggestion + subsequent rejection → rule unsuppressed and priority_adjustment set to +1. REJECTION_FEEDBACK event logged.

New physician inherits specialty cohort defaults (>0.70 acceptance → +1, <0.30 → -1, otherwise 0).

Cohort with < 10 physicians → aggregate not used, default priority applies.

Priority recalculation: acceptance_rate > 0.70 with 5+ observations → +1. <0.30 with 5+ → -1. Otherwise → 0.

Tier B removal: removal rate > 50% over 10+ pre-applied → demoted to Tier C. Below threshold → no demotion.

## 14.4 Digest Tests

Weekly digest generated for active providers with suggestion activity.

Providers with no activity skipped (no empty digest).

Category breakdown correctly aggregates generated/accepted/dismissed counts and revenue impact.

INTEL_WEEKLY_DIGEST notification event emitted per provider with correct payload.

Audit event logged for each digest generation.

## 14.5 Integration Tests

Create AHCIP claim → Tier 1 suggestions generated → accept suggestion → claim updated → revalidation triggered.

Create WCB claim approaching timing deadline → WCB_TIMING suggestion generated → shows correct fee tiers.

SOMB version update → affected rules identified (updated/deprecated/new) → change analysis generated per physician → SOMB_CHANGE_IMPACT notification emitted.

Physician dismisses suggestions for 3 months → priority adjustments reflected → LOW suggestions collapsed in UI.

Re-analysis after claim update: preserved ACCEPTED/DISMISSED suggestions, new PENDING suggestions generated from updated context.

WebSocket: subscribe to claim channel → Tier 2 completes → tier2_complete event broadcast with new suggestions.

Import-sourced claim with CONNECT_CARE_CSV → bedside-contingent rules resolve to Tier A → after-hours modifier auto-applied.

# 15. Open Questions

| # | Question | Context |
| --- | --- | --- |
| 1 | Which self-hosted LLM model performs best on Alberta billing domain tasks? | Need to evaluate candidates (DeepSeek 7B/13B, Llama variants, Mistral) on a billing-specific benchmark. Benchmark should test modifier eligibility reasoning, code alternative justification, and SOMB rule interpretation. |
| 2 | Should Tier 2 analysis run on every claim, or only when Tier 1 produces no suggestions? | Running on every claim maximises coverage but increases GPU utilisation. Running only on Tier 1-empty claims reduces cost but may miss nuanced optimisations. |
| 3 | Should the learning loop track delegate acceptance separately from physician acceptance? | Delegates may have different billing expertise than the physician they serve. Treating their acceptance/dismissal as equivalent may bias the learning loop. |
| 4 | What is the right suppression threshold? 5 consecutive dismissals may be too aggressive or too conservative. | Need real-world data. Configurable per physician as a preference? |
| 5 | Should rule creation require Reference Data linkage, or can rules exist independently? | Linking every rule to a specific SOMB/GR source ensures traceability but may limit rule flexibility for pattern-based suggestions. |
| 6 | When should the AI support chatbot (Phase 1.5) be built? | Uses same LLM infrastructure. Build after collecting real physician support queries to calibrate. Separate domain spec needed. |

# 16. Document Control

This document specifies the Intelligence Engine (AI Billing Coach). It is consumed by the Claim Lifecycle (Domain 4) which sends claim context post-validation and stores suggestions on the claim record.

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | Intelligence Engine (Domain 7 of 13) |
| Build sequence position | 7th |
| Dependencies | Domain 2 (Reference Data), Domain 4.0 (Claim Lifecycle Core), Domain 5 (Provider Management) |
| Consumed by | Domain 4.0 (suggestions on claims), Domain 4.1 (AHCIP analysis), Domain 4.2 (WCB analysis), Domain 8 (Analytics), Domain 9 (Notification Service — digests and SOMB change alerts) |
| Infrastructure | Self-hosted LLM on DigitalOcean Toronto via OpenAI-compatible API. Same model infrastructure reused for Phase 1.5 AI support chatbot. |
| Version | 2.0 |
| Date | February 2026 |
| Next domain in critical path | Domain 8 (Analytics & Reporting) |
