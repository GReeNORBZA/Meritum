# Meritum_Domain_07_Intelligence_Engine

MERITUM

Functional Requirements

Intelligence Engine

Domain 7 of 13  |  Critical Path: Position 7

Meritum Health Technologies Inc.

Version 1.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The Intelligence Engine is Meritum's AI Billing Coach. It analyses claims after the physician enters them and generates actionable suggestions to optimise billing accuracy and revenue. The engine operates as an advisory system — it never blocks submission and never modifies claims without the physician's explicit acceptance.

The core design principle is that physicians are already good at medicine; they are often not good at billing. The Intelligence Engine bridges this gap by applying billing expertise programmatically — catching missed modifiers, identifying code combination opportunities, flagging potential rejections before they happen, and surfacing patterns the physician would not notice manually.

## 1.2 Three-Tier Architecture

The Intelligence Engine uses a three-tier architecture that prioritises deterministic accuracy over AI novelty. Most suggestions come from Tier 1 (rules engine) with zero LLM cost. Tier 2 (LLM) handles nuanced cases. Tier 3 flags genuinely complex situations for human review.

## 1.3 Scope

Post-entry claim analysis: evaluate claims after physician saves, before submission

Suggestion generation: modifier recommendations, code alternatives, missed billing detection, rejection prevention

Tier 1 rules engine: deterministic billing rules derived from SOMB, governing rules, and WCB policies

Tier 2 LLM integration: self-hosted model for natural-language explanations and nuanced analysis

Tier 3 review flagging: complex cases flagged with citations to authoritative sources

Learning loop: adapt suggestion priority and relevance based on physician's specialty, patterns, and acceptance/dismissal history

Contextual help: tooltip content and inline guidance driven by Reference Data help_text fields

SOMB change impact analysis: when Reference Data is updated, assess impact on physician's typical billing patterns

## 1.4 Out of Scope

Claim validation (Domain 4.0 validation engine — Intelligence Engine is advisory, not gating)

Claim modification (suggestions are proposals; the physician accepts or dismisses)

Clinical decision support (Meritum is a billing platform, not clinical)

AI-driven customer support chatbot (Phase 1.5 — built on same LLM infrastructure but separate domain)

Automated coding from clinical notes (future enhancement; requires EMR integration)

## 1.5 Domain Dependencies

# 2. Suggestion Model

## 2.1 Suggestion Structure

Each suggestion is a structured object stored in the claim's ai_coach_suggestions JSONB array (Domain 4.0, claims table).

## 2.2 Suggestion Categories

## 2.3 Priority Assignment

Suggestion priority is determined by a combination of revenue impact and rejection risk:

HIGH: Revenue impact > $20 or rejection risk > 80% confidence. Displayed prominently with attention indicator.

MEDIUM: Revenue impact $5–$20 or rejection risk 50–80%. Standard display.

LOW: Revenue impact < $5, informational, or documentation suggestions. Collapsed by default, expandable.

Priority thresholds are configurable per physician specialty (radiologists have higher claim volumes with lower per-claim value; thresholds adjust accordingly).

# 3. Tier 1: Deterministic Rules Engine

## 3.1 Architecture

The Tier 1 engine is a pure rules engine with zero LLM dependency. It evaluates claims against a library of billing rules derived from the SOMB schedule, governing rules, and WCB policies. Rules are expressed as condition→action pairs where conditions are evaluated against claim data and Reference Data, and actions generate suggestions.

This engine runs synchronously during claim validation. Suggestions are available immediately after the physician saves a claim. There is no latency or cost associated with Tier 1 analysis.

## 3.2 Rule Structure

## 3.3 Rule Condition Language

Rule conditions are evaluated against a claim context object that includes claim fields, patient demographics, provider context, and Reference Data lookups. The condition language supports:

Field comparison: claim.health_service_code == '03.04A'

Existence check: claim.modifier_1 IS NULL

Set membership: claim.health_service_code IN ref.cmgp_eligible_codes

Temporal logic: claim.date_of_service IS weekday AND claim.shift_start > '17:00'

Cross-claim queries: COUNT(claims WHERE patient_id = :patient AND dos_month = :month AND hsc = :code) >= ref.gr3_limit

Nested conditions: AND, OR, NOT combinators

Conditions are parsed and evaluated by a lightweight expression evaluator. No SQL injection risk — conditions operate on a pre-fetched context object, not raw database queries.

## 3.4 MVP Rule Library

The initial Tier 1 rule library targets the highest-value suggestions for Meritum's primary user base (rural Alberta GPs). Rules are added incrementally as Reference Data is populated. The MVP rule categories:

### 3.4.1 Modifier Eligibility Rules (~30 rules)

CMGP eligibility: HSC code in CMGP-eligible list AND no CMGP modifier present → suggest CMGP

After-hours eligibility: DOS time qualifies for AFHR AND no after-hours modifier → suggest AFHR

RRNP eligibility: provider location qualifies AND RRNP not applied → note RRNP premium

Shadow billing: ARP physician AND no TM modifier → suggest TM

Time-based code duration: time_spent missing or below threshold for time-based HSC → flag

### 3.4.2 Rejection Prevention Rules (~40 rules)

GR 3 visit limits: same patient + same code + same period exceeds limit → warn

GR 8 referral required: specialist consultation without referring practitioner → error-level suggestion

Diagnostic code required: HSC category requires DI code and none present → flag

Modifier combination conflicts: mutually exclusive modifiers both present → flag

90-day window approaching: DOS within 7 days of deadline → timing warning

### 3.4.3 WCB-Specific Rules (~20 rules)

Timing tier awareness: calculate current tier and fee, show deadline for next tier → urgency suggestion

Form completeness: optional fields that improve acceptance rates → completeness suggestion

Premium code eligibility: 351 premium applicable AND not claimed → suggest

Follow-up chain: parent claim exists but follow-up not yet created within expected window → remind

### 3.4.4 Pattern-Based Rules (~15 rules)

Missed billing patterns: physician consistently bills Code A but never Code B when Code B is commonly billed alongside → suggest review

Under-utilised modifiers: physician's modifier usage rate below specialty average → educational suggestion

High rejection codes: physician has >20% rejection rate on specific code → pre-emptive guidance

# 4. Tier 2: LLM Integration

## 4.1 Architecture

Tier 2 uses a self-hosted open-source LLM (DeepSeek-class or equivalent) deployed on Meritum infrastructure (DigitalOcean Toronto). Self-hosting ensures zero per-query API fees, Canadian data residency for PHI-adjacent context, and no dependency on external AI providers.

The LLM is not used for billing rule evaluation (that is Tier 1's job). It is used for:

Natural-language explanations: Translating deterministic rule outputs into physician-friendly explanations

Nuanced analysis: Cases where the billing rule is conditional on clinical context that Meritum cannot fully determine (e.g., 'If this was a comprehensive visit, CMGP applies')

Code alternative reasoning: Explaining why an alternative HSC code may be more appropriate, considering the clinical context described in claim fields

SOMB change summaries: Generating plain-language summaries of SOMB updates and their impact on the physician's billing

## 4.2 Prompt Architecture

The LLM receives a structured prompt containing:

System prompt: Billing domain expert instructions. Fixed per deployment. Includes constraints (never fabricate rules, always cite SOMB/GR sources, acknowledge uncertainty).

Context block: Claim data (anonymised where possible — no patient name, PHN replaced with placeholder), provider specialty, relevant SOMB rules from Reference Data, Tier 1 rule evaluation results.

Task instruction: Specific analysis request (e.g., 'Explain why CMGP may apply to this encounter and what conditions must be met').

The LLM never receives raw PHI (patient PHN, name). Claim context is anonymised with placeholder values for patient-identifying fields. The LLM operates on billing structure (codes, modifiers, dates, clinical codes) not patient identity.

## 4.3 LLM Response Processing

Structured output: LLM is prompted to return JSON with defined fields (explanation, confidence, source_reference). Free-text responses are post-processed into the suggestion structure.

Confidence scoring: LLM self-reports confidence. Suggestions below 0.60 confidence are routed to Tier 3 (review recommended) rather than displayed as Tier 2 suggestions.

Hallucination guard: LLM output is validated against Reference Data. If the LLM cites a SOMB section or rule that does not exist in Reference Data, the suggestion is suppressed and logged for rule library improvement.

Latency budget: Tier 2 analysis has a 3-second timeout. If the LLM does not respond within 3 seconds, the claim proceeds with Tier 1 suggestions only. Tier 2 results are delivered asynchronously and appended when available.

## 4.4 Infrastructure

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

Title: Describes the area of concern (e.g., 'Surgical coding rules may affect this claim')

Description: Plain-language explanation of the ambiguity or complexity

Source reference: Specific SOMB section, governing rule number, or WCB policy clause

Source URL: Direct link to the authoritative document

No suggested_changes: Field is null. No one-click acceptance. Physician must review and decide.

No revenue_impact: Cannot be calculated for ambiguous cases.

No confidence score: Explicitly null to signal human review is needed.

# 6. Learning Loop

## 6.1 Signals

The learning loop adapts the Intelligence Engine to each physician's billing patterns over time. It collects signals from:

Suggestion acceptance rate: Which categories and specific rules does this physician consistently accept? Increase priority.

Suggestion dismissal rate: Which suggestions does this physician consistently dismiss? Decrease priority or suppress after N consecutive dismissals.

Dismissal reasons: Free-text reasons provide qualitative signal. Common reasons may indicate a rule needs refinement.

Rejection history: Claims rejected by AHCIP/WCB after the physician dismissed a REJECTION_RISK suggestion → strong signal that the rule was correct.

Billing patterns: Frequency of code/modifier usage relative to specialty average. Unusual patterns trigger exploratory suggestions.

Specialty cohort: Aggregate acceptance/dismissal rates across all physicians of the same specialty. New physicians start with specialty defaults.

## 6.2 Adaptation Mechanisms

## 6.3 Privacy Constraints

The learning loop operates on billing patterns (code frequencies, modifier usage, acceptance rates) not clinical data. No patient-identifying information enters the learning loop. Specialty cohort aggregation requires minimum 10 physicians per cohort before aggregate patterns are used — smaller cohorts risk de-identification.

# 7. Data Model

Suggestions themselves are stored on the claim (Domain 4.0, claims.ai_coach_suggestions JSONB). This domain owns the rule library and the learning loop state.

## 7.1 Rules Table (ai_rules)

## 7.2 Provider Learning State Table (ai_provider_learning)

Per-physician learning state for each rule. Tracks acceptance/dismissal history and current priority adjustments.

Constraints: (provider_id, rule_id) unique. Created lazily on first suggestion for this physician+rule pair.

## 7.3 Specialty Cohort Aggregates Table (ai_specialty_cohorts)

Aggregated acceptance/dismissal rates per specialty per rule. Updated nightly. Used to initialise new physicians.

## 7.4 Suggestion Audit Log (ai_suggestion_events)

Append-only log of all suggestion lifecycle events. Used for learning loop analysis and platform-wide metrics.

# 8. API Contracts

## 8.1 Suggestion Endpoints (Consumed by Domain 4)

## 8.2 Learning & Preferences (Physician-facing)

## 8.3 Rule Management (Internal / Admin)

## 8.4 SOMB Change Analysis (Consumed by Notification Service)

# 9. Contextual Help System

The contextual help system provides in-app education at every point where billing complexity surfaces. It is driven by Reference Data help_text fields and is distinct from the AI Coach suggestions (which are claim-specific recommendations).

## 9.1 Help Content Types

## 9.2 Help Content Source

Help content is authored in Reference Data (Domain 2) as part of the code/rule/modifier records. Each Reference Data entity has a help_text field (plain language), a source_reference field (SOMB section or GR number), and an optional source_url field (link to official document). The Intelligence Engine does not generate help content — it consumes it from Reference Data and surfaces it in the UI context.

# 10. Security

PHI isolation from LLM: Patient-identifying information (PHN, name) is stripped from claim context before Tier 2 LLM analysis. The LLM receives billing structure (codes, modifiers, dates, clinical codes, provider specialty) but never patient identity.

Self-hosted LLM: No data leaves Meritum infrastructure. No external API calls for AI analysis. Canadian data residency maintained.

Learning data is billing patterns: Acceptance rates, code frequencies, modifier usage. No PHI enters the learning loop tables.

Specialty cohort privacy: Minimum 10 physicians per cohort before aggregates are computed. Prevents de-identification of small specialty groups.

Rule library access: Rules viewable by physicians (transparency). Rule creation/modification is admin-only.

Suggestion audit log: All suggestion lifecycle events logged. Supports investigation of AI Coach accuracy and physician satisfaction.

# 11. Testing Requirements

## 11.1 Tier 1 Tests

Each MVP rule (~105 rules) tested with positive and negative claim context

CMGP suggestion: eligible claim without CMGP → suggestion generated. Claim with CMGP → no suggestion.

GR 3 rejection risk: visit limit exceeded → HIGH priority rejection warning

WCB timing: claim approaching tier downgrade → timing suggestion with correct fee values

Specialty filter: rule with specialty_filter = ['GP'] does not fire for specialist claims

Multiple rules on same claim: correct prioritisation and no duplicates

## 11.2 Tier 2 Tests

LLM responds within 3-second timeout → suggestion appended to claim

LLM timeout → Tier 1 suggestions unaffected, Tier 2 delivered asynchronously when available

LLM confidence < 0.60 → escalated to Tier 3, not shown as Tier 2

LLM cites non-existent SOMB section → suggestion suppressed, hallucination logged

PHI stripping: verify patient PHN and name are replaced with placeholders in LLM prompt

LLM instance down → graceful fallback to Tier 1 + Tier 3 only

## 11.3 Learning Loop Tests

Accept suggestion → times_accepted increments, consecutive_dismissals resets to 0

Dismiss suggestion 5 times consecutively → rule suppressed for that physician

Suppressed rule → no longer generates suggestions for that physician

Un-suppress rule → rule resumes generating suggestions

Rejection feedback: dismissed REJECTION_RISK suggestion + subsequent rejection → rule re-enabled and priority increased

New physician inherits specialty cohort defaults

Cohort with < 10 physicians → aggregate not used, default priority applies

## 11.4 Integration Tests

Create AHCIP claim → Tier 1 suggestions generated → accept suggestion → claim updated → revalidation passes

Create WCB claim approaching timing deadline → WCB_TIMING suggestion generated → shows correct fee tiers

SOMB version update → affected rules evaluated against new version → change analysis generated per physician

Physician dismisses suggestions for 3 months → priority adjustments reflected → LOW suggestions collapsed in UI

# 12. Open Questions

# 13. Document Control

This document specifies the Intelligence Engine (AI Billing Coach). It is consumed by the Claim Lifecycle (Domain 4) which sends claim context post-validation and stores suggestions on the claim record.

| Tier | Engine | Cost | Use Case |
| --- | --- | --- | --- |
| Tier 1 | Deterministic Rules Engine | Zero marginal cost. Pure logic. | Modifier eligibility, code combinations, governing rule checks, missed billing patterns. Handles ~80% of suggestions. |
| Tier 2 | Self-Hosted LLM | Low (self-hosted inference). No per-query API fees. | Natural-language explanations, nuanced clinical-billing mapping, complex modifier rationale. Handles ~15% of suggestions. |
| Tier 3 | Review Recommended | Zero. Flags for human review. | Genuinely ambiguous cases. Links to SOMB section, governing rule, or WCB policy. Handles ~5% of cases. |

| Domain | Direction | Interface |
| --- | --- | --- |
| 2 Reference Data | Consumed | SOMB codes, governing rules, modifiers, code combinations, help_text, source references. The knowledge base for Tier 1 rules and Tier 3 citations. |
| 4.0 Claim Lifecycle Core | Consumed by | Claim context sent post-validation. Suggestions stored on claim's ai_coach_suggestions JSONB field. |
| 4.1 AHCIP Pathway | Consumed by | AHCIP-specific suggestions: modifier eligibility, GR compliance, fee optimisation. |
| 4.2 WCB Pathway | Consumed by | WCB-specific suggestions: documentation completeness, timing tier awareness, form type guidance. |
| 5 Provider Management | Consumed | Physician specialty, practice locations, billing patterns for learning loop calibration. |
| 8 Analytics | Consumed by | Suggestion acceptance rates, revenue impact metrics, pattern data for learning loop. |

| Field | Type | Description |
| --- | --- | --- |
| suggestion_id | UUID | Unique identifier for this suggestion instance |
| tier | INTEGER | 1, 2, or 3. Identifies which engine generated the suggestion. |
| category | VARCHAR(30) | Suggestion category (Section 2.2) |
| priority | VARCHAR(10) | HIGH, MEDIUM, LOW. Determines display order and visual emphasis. |
| title | VARCHAR(200) | Short actionable title shown in the suggestion card (e.g., 'Add CMGP modifier') |
| description | TEXT | Detailed explanation of why this suggestion applies and what the physician should do. |
| revenue_impact | DECIMAL(10,2) | Estimated fee difference if suggestion is accepted. Null if not calculable. Positive = more revenue. |
| confidence | DECIMAL(3,2) | 0.00–1.00. Tier 1 always 1.00 (deterministic). Tier 2 varies. Tier 3 always null (human review needed). |
| source_reference | VARCHAR(200) | Authoritative source: SOMB section, governing rule, WCB policy reference. Always populated. |
| source_url | VARCHAR(500) | Direct link to authoritative source document when available. |
| suggested_changes | JSONB | Structured change proposal: {field, current_value, suggested_value}. For one-click acceptance. |
| status | VARCHAR(20) | PENDING, ACCEPTED, DISMISSED. Default: PENDING. |
| dismissed_reason | TEXT | Physician's optional reason for dismissal. Used in learning loop. |
| created_at | TIMESTAMPTZ | When the suggestion was generated |
| resolved_at | TIMESTAMPTZ | When the physician accepted or dismissed |
| resolved_by | UUID FK | Who resolved (physician or delegate with AI_COACH_REVIEW permission) |

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

| Field | Type | Description |
| --- | --- | --- |
| rule_id | UUID | Unique rule identifier |
| name | VARCHAR(100) | Human-readable rule name (e.g., 'CMGP Modifier Eligibility') |
| category | VARCHAR(30) | Maps to suggestion category (Section 2.2) |
| claim_type | VARCHAR(10) | AHCIP, WCB, or BOTH. Which pathway this rule applies to. |
| conditions | JSONB | Structured condition tree. Evaluated against claim context. |
| suggestion_template | JSONB | Template for the generated suggestion (title, description with placeholders, revenue_impact formula, source_reference). |
| specialty_filter | JSONB | Array of specialty codes this rule applies to. Null = all specialties. |
| priority_formula | VARCHAR(100) | Expression to calculate priority (e.g., 'revenue_impact > 20 ? HIGH : MEDIUM') |
| is_active | BOOLEAN | Active rules are evaluated. Inactive rules are skipped. |
| somb_version | VARCHAR(20) | SOMB version this rule was derived from. For version-aware evaluation. |
| created_at | TIMESTAMPTZ |  |
| updated_at | TIMESTAMPTZ |  |

| Component | Specification |
| --- | --- |
| Model | Self-hosted open-source LLM. Model selection based on billing domain evaluation (accuracy on modifier/code suggestions). Initial candidate: DeepSeek-class 7B–13B parameter model. |
| Hosting | DigitalOcean Toronto (same region as application). GPU droplet or inference-optimised instance. Canadian data residency maintained. |
| Scaling | Single instance sufficient for MVP (<100 physicians). Horizontal scaling via request queue if needed. |
| Cost model | Fixed infrastructure cost (~$200–$500/month for GPU instance). Zero per-query cost. Contrast with API-based models at $0.01–$0.10/query. |
| Fallback | If LLM instance is unavailable, all analysis falls through to Tier 1 (deterministic) and Tier 3 (review recommended). No degradation in safety-critical validation. |

| Mechanism | Behaviour |
| --- | --- |
| Priority adjustment | Suggestion priority shifts based on physician's historical acceptance rate for that rule/category. Frequently accepted → stays at assigned priority. Frequently dismissed → demoted to LOW. Never promoted above the rule-defined maximum. |
| Suppression threshold | After 5 consecutive dismissals of the same rule for the same physician, the rule is suppressed (not generated). Physician can re-enable suppressed rules in settings. |
| Specialty calibration | New physicians inherit the median acceptance rates from their specialty cohort. Personalisation develops over the first ~50 claims. |
| Rejection feedback | If a claim is rejected for a reason that a dismissed REJECTION_RISK suggestion predicted, the system re-enables the rule and increases its priority permanently. |
| Seasonal patterns | Some billing patterns are seasonal (flu season, allergy season). The learning loop uses rolling 90-day windows, not lifetime averages. |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| rule_id | UUID | No | Primary key |
| name | VARCHAR(100) | No | Human-readable rule name |
| category | VARCHAR(30) | No | Suggestion category |
| claim_type | VARCHAR(10) | No | AHCIP, WCB, or BOTH |
| conditions | JSONB | No | Condition tree evaluated against claim context |
| suggestion_template | JSONB | No | Title, description (with placeholders), revenue formula, source_reference |
| specialty_filter | JSONB | Yes | Array of specialty codes. Null = all. |
| priority_formula | VARCHAR(100) | No | Priority calculation expression |
| is_active | BOOLEAN | No | Whether this rule is currently evaluated |
| somb_version | VARCHAR(20) | Yes | SOMB version this rule was derived from |
| created_at | TIMESTAMPTZ | No |  |
| updated_at | TIMESTAMPTZ | No |  |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| learning_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers |
| rule_id | UUID FK | No | FK to ai_rules |
| times_shown | INTEGER | No | Total times this rule generated a suggestion for this physician |
| times_accepted | INTEGER | No | Times the physician accepted |
| times_dismissed | INTEGER | No | Times dismissed |
| consecutive_dismissals | INTEGER | No | Current streak of consecutive dismissals. Resets on acceptance. |
| is_suppressed | BOOLEAN | No | True when consecutive_dismissals >= 5. Physician can manually un-suppress. |
| priority_adjustment | INTEGER | No | Adjustment to base priority: -1 (demote), 0 (no change), +1 (promote). Derived from acceptance rate. |
| last_shown_at | TIMESTAMPTZ | Yes | When this rule last generated a suggestion for this physician |
| last_feedback_at | TIMESTAMPTZ | Yes | When the physician last accepted or dismissed |
| created_at | TIMESTAMPTZ | No |  |
| updated_at | TIMESTAMPTZ | No |  |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| cohort_id | UUID | No | Primary key |
| specialty_code | VARCHAR(10) | No | Specialty code |
| rule_id | UUID FK | No | FK to ai_rules |
| physician_count | INTEGER | No | Number of physicians contributing to this aggregate. Minimum 10 for use. |
| acceptance_rate | DECIMAL(5,4) | No | Aggregate acceptance rate (0.0000–1.0000) |
| median_revenue_impact | DECIMAL(10,2) | Yes | Median revenue impact when accepted |
| updated_at | TIMESTAMPTZ | No | Last recalculation timestamp |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| event_id | UUID | No | Primary key |
| claim_id | UUID FK | No | FK to claims |
| suggestion_id | UUID | No | Suggestion ID from the claim's JSONB |
| rule_id | UUID FK | Yes | FK to ai_rules. Null for Tier 2/3 suggestions not from rule library. |
| provider_id | UUID FK | No | FK to providers |
| event_type | VARCHAR(20) | No | GENERATED, ACCEPTED, DISMISSED, SUPPRESSED, UNSUPPRESSED |
| tier | INTEGER | No | 1, 2, or 3 |
| category | VARCHAR(30) | No | Suggestion category |
| revenue_impact | DECIMAL(10,2) | Yes | Revenue impact at time of event |
| dismissed_reason | TEXT | Yes | For DISMISSED events: physician's reason |
| created_at | TIMESTAMPTZ | No |  |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/intelligence/analyse | Submit claim context for analysis. Returns Tier 1 suggestions synchronously. Triggers Tier 2 analysis asynchronously (results delivered via WebSocket or polling). Body: claim context object. |
| GET | /api/v1/intelligence/claims/{claim_id}/suggestions | Get all suggestions for a claim. Returns from claim's JSONB (fast read). |
| POST | /api/v1/intelligence/suggestions/{id}/accept | Accept a suggestion. Applies suggested_changes to the claim (Domain 4 processes the change). Updates learning state. |
| POST | /api/v1/intelligence/suggestions/{id}/dismiss | Dismiss a suggestion. Optional reason. Updates learning state and consecutive_dismissals. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/intelligence/me/learning-state | Get physician's learning state summary: suppressed rules, top accepted categories, dismissal patterns. |
| POST | /api/v1/intelligence/me/rules/{rule_id}/unsuppress | Manually un-suppress a rule that was auto-suppressed after 5 consecutive dismissals. |
| PUT | /api/v1/intelligence/me/preferences | Set AI Coach preferences: enable/disable specific categories, set priority thresholds. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/intelligence/rules | List all rules with status and statistics. |
| POST | /api/v1/intelligence/rules | Create a new rule. Admin only. |
| PUT | /api/v1/intelligence/rules/{id} | Update a rule (conditions, template, specialty filter). |
| PUT | /api/v1/intelligence/rules/{id}/activate | Activate/deactivate a rule. |
| GET | /api/v1/intelligence/rules/{id}/stats | Get rule performance: acceptance rate, revenue impact, suppression rate across all physicians. |
| POST | /api/v1/intelligence/cohorts/recalculate | Trigger specialty cohort recalculation (normally nightly). |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/intelligence/somb-change-analysis | Given old and new SOMB versions, generate per-physician impact analysis. Returns affected rules, changed codes, and plain-language summary for notification. |

| Type | Description |
| --- | --- |
| Field tooltips | Plain-language explanation of every billing field. E.g., hovering over 'CMGP' shows: 'Comprehensive modifier for encounters over 15 minutes. Applies to qualifying office visit codes.' |
| Validation warning help | When a validation warning fires, inline help explains the rule and suggests corrective action. Driven by Reference Data rule help_text. |
| Governing rule summaries | Expandable cards showing the governing rule in plain language with link to official SOMB source. Available on any code where GR applies. |
| WCB form guidance | Per-field guidance on WCB forms explaining what WCB expects. E.g., 'Objective findings: describe what you observed, not what the patient reports.' |
| SOMB change alerts | When a code or rule the physician frequently uses has changed, an in-app alert explains the change in plain language. |

| # | Question | Context |
| --- | --- | --- |
| 1 | Which self-hosted LLM model performs best on Alberta billing domain tasks? | Need to evaluate candidates (DeepSeek 7B/13B, Llama variants, Mistral) on a billing-specific benchmark. Benchmark should test modifier eligibility reasoning, code alternative justification, and SOMB rule interpretation. |
| 2 | Should Tier 2 analysis run on every claim, or only when Tier 1 produces no suggestions? | Running on every claim maximises coverage but increases GPU utilisation. Running only on Tier 1-empty claims reduces cost but may miss nuanced optimisations. |
| 3 | Should the learning loop track delegate acceptance separately from physician acceptance? | Delegates may have different billing expertise than the physician they serve. Treating their acceptance/dismissal as equivalent may bias the learning loop. |
| 4 | What is the right suppression threshold? 5 consecutive dismissals may be too aggressive or too conservative. | Need real-world data. Configurable per physician as a preference? |
| 5 | Should rule creation require Reference Data linkage, or can rules exist independently? | Linking every rule to a specific SOMB/GR source ensures traceability but may limit rule flexibility for pattern-based suggestions. |
| 6 | When should the AI support chatbot (Phase 1.5) be built? | Uses same LLM infrastructure. Build after collecting real physician support queries to calibrate. Separate domain spec needed. |

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | Intelligence Engine (Domain 7 of 13) |
| Build sequence position | 7th |
| Dependencies | Domain 2 (Reference Data), Domain 4.0 (Claim Lifecycle Core), Domain 5 (Provider Management) |
| Consumed by | Domain 4.0 (suggestions on claims), Domain 4.1 (AHCIP analysis), Domain 4.2 (WCB analysis), Domain 8 (Analytics) |
| Infrastructure | Self-hosted LLM on DigitalOcean Toronto. Same model infrastructure reused for Phase 1.5 AI support chatbot. |
| Version | 1.0 |
| Date | February 2026 |
| Next domain in critical path | Domain 8 (Analytics & Reporting) |

