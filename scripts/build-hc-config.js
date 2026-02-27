#!/usr/bin/env node
/**
 * build-hc-config.js — Generates configs/help-centre.json
 *
 * Produces the task config for all 44 help centre tasks (43 articles + 1 validation).
 * Run once, then use generate-tasks.js to produce manifests and prompts.
 *
 * Usage: node scripts/build-hc-config.js
 */

const fs = require('fs');
const path = require('path');

const outputPath = path.resolve(__dirname, '..', 'configs', 'help-centre.json');

// --- Shared context included in every task ---
const SHARED_CONTEXT = [
  "**Voice & Style Rules (Content Brief Section 3):**",
  "- Lead with the answer. First sentence or paragraph resolves the question. Context and explanation follow.",
  "- Use numbered steps for procedural content (how to do X). Use paragraphs for conceptual content (how X works).",
  "- Target 300-600 words for procedural articles; 600-1,000 for reference articles.",
  "- Use headings to break up longer articles, but do not over-structure short ones. A 300-word article with four headings is harder to read than three paragraphs.",
  "- Include cross-links to related articles using relative markdown paths: [text](/help-centre/category/slug). Link once per concept, not every mention.",
  "- Use the same terms the platform uses. If the UI says 'submission preferences', write 'submission preferences', not 'submission settings'.",
  "- Rules engine and advice engine: use these terms consistently. Never call the advice engine 'AI' or 'machine learning'.",
  "- Spell out all abbreviations on first use in each article: Alberta Health Care Insurance Plan (AHCIP), Workers' Compensation Board (WCB), Schedule of Medical Benefits (SOMB), etc. Abbreviate thereafter.",
  "- Use 'physician' not 'doctor', 'provider', or 'clinician' (unless referring to a specific non-physician provider type).",
  "- No marketing language, pricing pitches, or competitive comparisons. The help centre is support, not sales.",
  "- No em dashes (U+2014) anywhere. Use semicolons, colons, or separate sentences instead.",
  "- No placeholder content: never write 'coming soon', 'to be determined', 'TBD', 'placeholder', or 'more details to follow'.",
  "- Do not reproduce copyrighted rate tables from the SOMB or WCB fee schedules. Reference them, explain how to read them, and link to the official source.",
  "- Do not use language that reads as AI-generated. Avoid filler phrases, forced transitions, and generic qualifiers. Write like a knowledgeable colleague explaining something over the phone.",
  "",
  "**Front Matter Schema (required in every article):**",
  "```yaml",
  "---",
  "title: \"Article Title Here\"",
  "category: category-slug-here",
  "slug: article-slug-here",
  "description: \"Brief description for search and index page.\"",
  "priority: 1",
  "last_reviewed: 2026-02-25",
  "review_cycle: on-change",
  "type: procedural",
  "---",
  "```",
  "",
  "**Output:** Write the complete markdown file to the specified path. Include front matter and full article body. Do not generate stubs or placeholder content. Every article must be self-contained: a physician landing on it from a search result should understand it without reading anything else first."
];

// --- Helper to build a task object ---
function task(id, description, category, slug, type, priority, reviewCycle, wordRange, build, frd, depends) {
  const verifyPath = `help-centre/${category}/${slug}.md`;
  const t = {
    id,
    description,
    verify: `node scripts/validate-article.js ${verifyPath}`,
    build: [
      `Write the help centre article: \`${verifyPath}\``,
      "",
      "**Front matter values for this article:**",
      `- title: "${description}"`,
      `- category: ${category}`,
      `- slug: ${slug}`,
      `- type: ${type}`,
      `- priority: ${priority}`,
      `- review_cycle: ${reviewCycle}`,
      `- last_reviewed: 2026-02-25`,
      `- description: (write a concise 1-sentence description for search/index)`,
      "",
      `**Word count target:** ${wordRange} (${type} article)`,
      "",
      ...build
    ],
    frd,
    context: SHARED_CONTEXT
  };
  if (depends) t.depends = depends;
  return t;
}

// ============================================================================
// SECTION 1: Tier 1 — Getting Started (7 tasks)
// ============================================================================
const section1 = {
  title: "Tier 1: Getting Started",
  tasks: [
    task("HC-001", "Setting up your professional profile", "getting-started", "setting-up-your-professional-profile", "procedural", 1, "on-change", "300-600",
      [
        "**Content scope:** Walk the physician through the professional profile setup during onboarding.",
        "Cover: billing number, CPSA registration number, legal name, specialty selection, physician type (GP, Specialist, Locum).",
        "Explain what each field is used for (billing number identifies you to Alberta Health, CPSA confirms your registration, etc.).",
        "Mention that this is Step 1 of the onboarding wizard and cannot be skipped.",
        "Note that specialty selection affects which SOMB codes appear in searches and which modifier suggestions the platform makes.",
        "Cross-link to: [Adding your business arrangement numbers](/help-centre/getting-started/adding-your-business-arrangement-numbers)"
      ],
      [
        "Domain 5 Section 1: Provider Management owns the physician's professional identity. Authoritative source for billing configuration.",
        "Domain 5 Section 2.1: Providers table fields: billing_number (unique), cpsa_registration_number (unique), specialty_code, physician_type, legal_name, status.",
        "Domain 5 Section 4.1: Profile Setup user stories (PRV-001 through PRV-004). PRV-001: physician enters billing number, CPSA, legal name during onboarding. System validates format and uniqueness.",
        "Domain 11 Section 2: Onboarding flow Step 1 Professional Identity (billing number, CPSA, legal name, creates provider record), Step 2 Specialty & Type (specialty dropdown, GP/Specialist/Locum)."
      ]
    ),

    task("HC-002", "Adding your business arrangement numbers", "getting-started", "adding-your-business-arrangement-numbers", "procedural", 1, "on-change", "300-600",
      [
        "**Content scope:** Explain what a Business Arrangement (BA) number is and how to add one (or two) during onboarding.",
        "Cover: what a BA number represents (your billing relationship with Alberta Health), where to find it, how to enter it.",
        "Explain the dual-BA setup for PCPCM physicians: they need both a PCPCM BA and a FFS BA.",
        "Mention the AHC11236 form: after entering your BA, Meritum pre-fills this form for you to print, sign, and submit to Alberta Health to link your BA to Meritum as your electronic submitter.",
        "Explain the PENDING status: your BA stays in PENDING state until Alberta Health processes the AHC11236 (2-4 weeks). You can create and validate claims while pending, but cannot submit batches until the BA is ACTIVE.",
        "Cross-link to: [Business arrangements in Alberta](/help-centre/billing-reference/business-arrangements-in-alberta), [PCPCM: Primary Care Panel and Continuity Model](/help-centre/billing-reference/pcpcm-primary-care-panel-and-continuity-model)"
      ],
      [
        "Domain 5 Section 2.2: Business Arrangements table. A physician may have one or two active BAs. Standard FFS physicians have one. PCPCM physicians have two: a PCPCM BA and a FFS BA. Maximum 2 active BAs per provider. ba_number unique across active records.",
        "Domain 11 Section 2: Onboarding Step 3 Business Arrangement: primary BA entry, PCPCM dual-BA guided flow, status starts PENDING, pre-fills AHC11236.",
        "Domain 11 Section 4: AHC11236 Form Pre-Fill. Links BA to accredited submitter (Meritum). Physician downloads pre-filled PDF, prints, signs, mails/faxes to Alberta Health. BA status: PENDING after submission, manual confirm after Alberta Health processes (2-4 weeks), ACTIVE allows batch submission."
      ]
    ),

    task("HC-003", "Configuring your practice locations", "getting-started", "configuring-your-practice-locations", "procedural", 1, "on-change", "300-600",
      [
        "**Content scope:** Walk through adding practice locations during onboarding.",
        "Cover: location name, functional centre code, facility number, address, community code.",
        "Explain that the functional centre determines which governing rules apply and whether RRNP premiums are eligible.",
        "Cover the locum scenario explicitly: physicians who work at multiple facilities can add multiple locations and select the correct one when creating each claim.",
        "Mention that one location must be set as the default.",
        "Explain RRNP eligibility: if the community code qualifies under the Rural and Remote Northern Program, the platform automatically calculates the RRNP premium percentage.",
        "Cross-link to: [RRNP: Rural and Remote Northern Program](/help-centre/billing-reference/rrnp-rural-and-remote-northern-program)"
      ],
      [
        "Domain 5 Section 2.3: Practice Locations table. A physician may practise at multiple locations (multi-site) or different locations in different months (locum). Each location maps to an AHCIP functional centre. Exactly one default location per provider. Community_code validated against Reference Data.",
        "Domain 5 Section 8: Locum Support. Multi-location management with per-claim location selection. Locum physicians work at multiple facilities across different communities, often in a single month.",
        "Domain 11 Section 2: Onboarding Step 4 Practice Location: name, functional centre, facility number, address, community code. RRNP auto-calculated from community code.",
        "Domain 2 Section 2: RRNP Community Rate Table. community_code, community_name, rrnp_percentage (7%-30%+). Consumed for RRNP premium calculations."
      ]
    ),

    task("HC-004", "Setting up WCB billing", "getting-started", "setting-up-wcb-billing", "procedural", 1, "on-change", "300-600",
      [
        "**Content scope:** Explain how to configure Workers' Compensation Board (WCB) billing during onboarding.",
        "Cover: WCB Contract ID, Role code, Skill code, and permitted form types.",
        "Explain that a physician may have multiple Contract IDs (e.g., GP billing under one contract, OIS under another).",
        "Note this is an optional onboarding step; not all physicians bill WCB.",
        "Explain that the Contract ID, Role, and Form Type together determine which WCB forms a physician can submit.",
        "Cross-link to: [WCB Alberta billing for physicians](/help-centre/billing-reference/wcb-alberta-billing-for-physicians), [Submitting WCB claims](/help-centre/submitting-claims/submitting-wcb-claims)"
      ],
      [
        "Domain 5 Section 2.5: WCB Configuration table. Stores the physician's WCB billing identity. A physician may have multiple Contract IDs (e.g., GP billing under 000001 and OIS under 000053). Each Contract ID maps to a Role and a set of permitted form types per the WCB Contract ID/Role/Form ID matrix.",
        "Domain 11 Section 2: Onboarding Step 5 WCB Configuration (optional): Contract ID, Role, Skill code, permitted form types.",
        "Domain 4.2 Section 2: WCB Form Types. 8 form types (C050E initial report, C050S specialist initial, C151 progress, C151S specialist progress, C568 consultation, C568A consultation amendment, C569 equipment/supplies, C570 invoice). Contract ID/Role/Form ID permission matrix determines which forms a practitioner can submit."
      ]
    ),

    task("HC-005", "Inviting a delegate", "getting-started", "inviting-a-delegate", "procedural", 1, "on-change", "300-600",
      [
        "**Content scope:** Explain how to invite a delegate and configure their permissions.",
        "Cover: what a delegate is (a non-physician user who performs billing tasks on your behalf), how to send an invitation (email with 72-hour expiry), how to choose permissions.",
        "Explain the permission presets (Full Access, Billing Only, View Only) and granular configuration.",
        "Cover what delegates can and cannot see/do: delegates cannot manage other delegates, cannot manage subscriptions, cannot export data, and cannot view audit logs by default.",
        "Explain multi-physician delegation: a single delegate can serve multiple physicians with independent permission sets.",
        "Cross-link to: [Managing delegates](/help-centre/your-account/managing-delegates), [Delegate access and data separation](/help-centre/security-compliance/delegate-access-and-data-separation)"
      ],
      [
        "Domain 1 Section 3: User Stories IAM-003 Delegate Invitation. Email with 72-hour token. Existing delegate can add physician. Permission configuration. Linkage activation on acceptance.",
        "Domain 1 Section 2: Roles & Permissions. Delegate has configurable permissions per physician. Cannot access DELEGATE_MANAGE, SUBSCRIPTION_MANAGE, DATA_EXPORT, AUDIT_VIEW by default.",
        "Domain 5 Section 3: Delegate Permission Model. Permission catalogue with preset templates (Full Access, Billing Only, View Only) or granular configuration. Multi-physician delegation: independent permission sets per physician-delegate pair. Context switching is explicit and logged.",
        "Domain 5 Section 2.6: Delegate Relationships table. (physician_id, delegate_user_id) unique for active relationships. A delegate can serve multiple physicians."
      ]
    ),

    task("HC-006", "Choosing your submission preferences", "getting-started", "choosing-your-submission-preferences", "procedural", 1, "on-change", "300-600",
      [
        "**Content scope:** Explain the three submission preference modes and how to choose one during onboarding.",
        "Cover the three modes:",
        "1. **Require Approval** (default): Every claim must be manually approved before it enters a Thursday batch.",
        "2. **Auto-submit clean**: Claims with no flags or warnings are automatically queued for the next Thursday batch. Flagged claims still require manual review.",
        "3. **Auto-submit all**: All claims (clean and flagged) are automatically queued. Use with caution.",
        "Explain that AHCIP and WCB preferences can be set independently.",
        "Note this is an optional onboarding step with sensible defaults.",
        "Cross-link to: [Submission preferences explained](/help-centre/submitting-claims/submission-preferences-explained)"
      ],
      [
        "Domain 5 Section 2.7: Submission Preferences table. Stores the physician's auto-submission configuration. One row per physician. Referenced by the batch assembly process.",
        "Domain 4.0 Section 2: Claim State Machine. Clean vs flagged classification. Tiered auto-submission model: Auto Clean (flagged held back), Auto All (everything queued), Require Approval (manual approval required for all).",
        "Domain 11 Section 2: Onboarding Step 6 Submission Preferences (optional). Auto Clean / Auto All / Require Approval with explanations. Defaults accepted if skipped."
      ]
    ),

    task("HC-007", "Your first Thursday submission: what to expect", "getting-started", "your-first-thursday-submission", "procedural", 1, "on-change", "300-600",
      [
        "**Content scope:** Walk a new physician through what happens during their first Thursday submission cycle.",
        "Cover the timeline: Thursday 12:00 MT cutoff, batch assembly (12:00-14:00), H-Link file generation and transmission, Friday assessment response.",
        "Explain what the physician needs to do before Thursday: ensure claims are validated and queued (or approved, depending on submission preferences).",
        "Explain what happens automatically: batch assembly groups claims by BA number, generates H-Link files, transmits to Alberta Health.",
        "Explain what to expect on Friday: assessment results arrive, claims move to paid/held/refused status.",
        "Set expectations: first batch may be small; this is normal.",
        "Cross-link to: [How the Thursday submission cycle works](/help-centre/submitting-claims/how-the-thursday-submission-cycle-works), [Understanding your assessment results](/help-centre/after-submission/understanding-your-assessment-results)"
      ],
      [
        "Domain 4.1 Section 3: Thursday Batch Cycle. Weekly rhythm: Thursday 12:00 MT cutoff, batch assembly (12:00-14:00), file generation, transmission, Friday assessment response, Friday payment. Batch assembly groups claims by physician + BA number.",
        "Domain 4.1 Section 4: H-Link File Generation. File structure: header, claim records, trailer. Transmission via SFTP/API. Security: TLS 1.3, encrypted files.",
        "Domain 4.1 Section 7: Assessment Response Ingestion. Friday assessment file retrieval from H-Link, parsing, claim matching, state transitions (accepted/assessed, rejected, adjusted), explanatory code resolution."
      ]
    )
  ]
};

// ============================================================================
// SECTION 2: Tier 1 — Submitting Claims Core (6 tasks)
// ============================================================================
const section2 = {
  title: "Tier 1: Submitting Claims Core",
  tasks: [
    task("HC-008", "Importing encounters from your EMR", "submitting-claims", "importing-encounters-from-your-emr", "procedural", 1, "on-change", "300-600",
      [
        "**Content scope:** Explain how to import claims from an EMR (Electronic Medical Record) system via CSV file upload.",
        "Cover: supported file formats (CSV, TSV), how to export from your EMR, the upload process, field mapping, validation results.",
        "Explain the import summary screen: total rows, rows parsed, rows with warnings, rows rejected, potential duplicates.",
        "Cover the Connect Care / SCC extract workflow: physicians using Connect Care can export a 'My Billing Codes' extract and import it directly.",
        "Explain that imported claims appear in the Unsubmitted queue as drafts for review before submission.",
        "Mention field mapping templates: once you map your EMR's columns to Meritum fields, the template is saved for future imports.",
        "Cross-link to: [Creating claims manually](/help-centre/submitting-claims/creating-claims-manually)"
      ],
      [
        "Domain 4.0 Section 3: Base Data Model. import_batches table for EMR imports. field_mapping_templates table for CSV column mapping. Claims created via import tagged with importSource metadata.",
        "Domain 4.0 Section 5: User Stories CLM-003 EMR Import. Upload CSV/TSV, delimiter detection, field mapping with saved templates, validation per row, summary screen (total/parsed/warnings/rejected/duplicates), physician confirms before claim creation.",
        "Domain 4 Section: Combined claim lifecycle covering import API, field mapping templates, supported formats."
      ]
    ),

    task("HC-009", "Using mobile claim entry", "submitting-claims", "using-mobile-claim-entry", "procedural", 1, "on-change", "300-600",
      [
        "**Content scope:** Explain how to log claims from a mobile device, focusing on the ED shift workflow and quick claim entry.",
        "Cover the ED shift workflow: start shift (select location), log patients as you see them (select patient, select code from favourites or search, modifiers auto-suggested), end shift (review summary), then finish on desktop.",
        "Cover quick claim entry: select patient, select code, save as draft. Takes under 30 seconds with recent patients and favourite codes.",
        "Explain favourite codes: a curated list of frequently used HSC codes with one-tap selection and default modifiers.",
        "Explain after-hours auto-detection: the platform suggests after-hours modifiers based on the time of your shift (evening, night, weekend, statutory holiday).",
        "Note that mobile creates AHCIP drafts only; WCB is too complex for mobile entry. Full validation and submission happens on desktop.",
        "Cross-link to: [Creating claims manually](/help-centre/submitting-claims/creating-claims-manually)"
      ],
      [
        "Domain 10 Section 2: ED Shift Workflow. 7 steps: start shift with location, log patient per encounter with timestamp, add codes/modifiers, quick notes, next patient, end shift with summary, desktop review. After-hours auto-detection (weekday evening 17:00-23:00 AFHR, night 23:00-08:00 NGHR, weekend/stat WKND).",
        "Domain 10 Section 3: Quick Claim Entry. Select patient (recent 20 or search), select code (favourites one-tap or search), modifiers (quick-toggle CMGP/AFHR/NGHR/TM), save as draft. AHCIP only, draft state only.",
        "Domain 10 Section 4: Favourite Codes. Max 30, custom labels, default modifiers per favourite, auto-seeded from 10 most frequent codes or specialty defaults."
      ]
    ),

    task("HC-010", "Creating claims manually", "submitting-claims", "creating-claims-manually", "procedural", 1, "on-change", "300-600",
      [
        "**Content scope:** Walk through the manual claim creation form step by step.",
        "Cover the fields: patient (search by PHN or name), HSC service code (search with autocomplete), date of service, location (defaults to your primary), modifiers, diagnostic code, referral practitioner (if required by governing rules).",
        "Explain what happens after saving: the claim enters 'draft' state, the validation engine runs checks, and the claim is classified as 'clean' (no issues) or 'flagged' (has warnings or errors to resolve).",
        "Explain the difference between errors (must fix before submission) and warnings (can submit but review recommended).",
        "Mention that the platform shows applicable modifiers alongside the HSC code selection.",
        "Cross-link to: [Understanding flags and suggestions on your claims](/help-centre/submitting-claims/understanding-flags-and-suggestions-on-your-claims)"
      ],
      [
        "Domain 4.0 Section 2: Claim State Machine. States: draft, validated, queued, submitted, assessed. Clean vs flagged classification based on validation results.",
        "Domain 4.0 Section 4: Validation Engine Architecture. Validation pipeline runs shared structural checks. Validation result format: errors (blocking), warnings (non-blocking), info. Runs on save, on queue, and pre-batch.",
        "Domain 4.0 Section 5: User Stories CLM-001 Manual Claim Creation. Claim entry form with code selection, location selection, modifier application, diagnostic code entry.",
        "Domain 4.1 Section 2: AHCIP Claim Data Elements. BA number, functional centre, HSC code, modifiers (1-3), diagnostic code, facility number, referral practitioner, encounter type."
      ]
    ),

    task("HC-011", "Understanding flags and suggestions on your claims", "submitting-claims", "understanding-flags-and-suggestions-on-your-claims", "procedural", 1, "on-change", "300-600",
      [
        "**Content scope:** Combined overview explaining both the rules engine (flags) and the advice engine (suggestions) and how they appear on claims.",
        "Explain the two systems:",
        "1. **Rules engine flags**: Automated checks that catch errors and potential issues before submission. Flags are either errors (must fix) or warnings (should review). Examples: missing referral for specialist consultation, modifier not eligible for this code, approaching 90-day submission deadline.",
        "2. **Advice engine suggestions**: Billing optimisation recommendations. Suggestions are optional; they highlight opportunities you might have missed. Examples: eligible modifier not applied, code alternative with higher reimbursement, pattern-based missed billing.",
        "Explain how to resolve flags vs how to act on suggestions.",
        "Emphasise that flags prevent rejected claims; suggestions help recover revenue.",
        "Cross-link to: [How the rules engine works](/help-centre/submitting-claims/how-the-rules-engine-works), [How the advice engine works](/help-centre/submitting-claims/how-the-advice-engine-works)"
      ],
      [
        "Domain 7 Section 1: Intelligence Engine overview. Three-tier architecture: Tier 1 (deterministic rules), Tier 2 (LLM analysis), Tier 3 (review recommended with citations).",
        "Domain 7 Section 2: Suggestion Model. Categories: MODIFIER_ADD, MODIFIER_REMOVE, CODE_ALTERNATIVE, MISSED_BILLING, REJECTION_RISK, etc. Priority: HIGH (>$20 or >80% rejection risk), MEDIUM ($5-$20), LOW (informational).",
        "Domain 4.0 Section 4: Validation Engine. Errors (blocking) vs warnings (non-blocking). Shared validation checks S1-S7. Runs on save and on queue.",
        "Domain 7 Section 3: Tier 1 Rules Engine. ~105 MVP rules covering modifier eligibility, rejection prevention, WCB timing, pattern-based suggestions."
      ]
    ),

    task("HC-012", "How the rules engine works", "submitting-claims", "how-the-rules-engine-works", "reference", 1, "on-change", "600-1000",
      [
        "**Content scope:** Deep dive into the rules engine (Tier 1 of the Intelligence Engine).",
        "Explain that the rules engine runs deterministic checks against Alberta Health requirements, SOMB governing rules, and known rejection patterns.",
        "Cover the types of checks: modifier eligibility (is this modifier valid for this code?), visit limits (governing rule 3), referral requirements (governing rule 8), 90-day submission window, diagnostic code requirements, modifier conflicts, PCPCM routing validation.",
        "Explain flag types: errors (claim cannot be submitted until resolved) vs warnings (claim can be submitted but may be rejected).",
        "Give examples of common flags and how to resolve them.",
        "Explain that the rules engine improves over time: if you consistently dismiss a suggestion and then get rejected, the rule priority increases.",
        "Cross-link to: [Understanding flags and suggestions on your claims](/help-centre/submitting-claims/understanding-flags-and-suggestions-on-your-claims), [How the advice engine works](/help-centre/submitting-claims/how-the-advice-engine-works)"
      ],
      [
        "Domain 7 Section 3: Tier 1 Deterministic Rules Engine. Pure rules engine with zero LLM cost. Rule structure: condition, action, priority formula. Condition language: field comparison, existence check, set membership, temporal logic, cross-claim queries.",
        "Domain 7 Section 3: MVP rule library (~105 rules): modifier eligibility (CMGP, AFHR, RRNP, TM, time-based), rejection prevention (GR 3 visit limits, GR 8 referral, diagnostic codes, modifier conflicts, 90-day window), WCB-specific (timing tier awareness, form completeness, 351 premium), pattern-based (missed billing, under-utilised modifiers, high rejection codes).",
        "Domain 7 Section 6: Learning Loop. Signals: acceptance rate, dismissal rate with reasons, rejection history. Adaptation: frequently dismissed rules demoted, 5 consecutive dismissals suppresses rule, dismissed then rejected re-enables and increases priority.",
        "Domain 4.1 Section 5: AHCIP Validation Rules. 19 checks (A1-A19): HSC code validity, BA number, governing rules (GR 1, 3, 5, 8, 10, 14, 18), modifier eligibility, diagnostic code requirements, 90-day window, RRNP eligibility."
      ]
    ),

    task("HC-013", "How the advice engine works", "submitting-claims", "how-the-advice-engine-works", "reference", 1, "on-change", "600-1000",
      [
        "**Content scope:** Deep dive into the advice engine (Tier 2 and Tier 3 of the Intelligence Engine).",
        "Explain that the advice engine analyses your claims and suggests billing optimisations you may have missed.",
        "Cover suggestion categories: modifier additions (eligible modifier not applied), code alternatives (similar code with higher reimbursement), missed billing opportunities (pattern detected in your history), and review recommended (complex scenarios where the platform cites the source and lets you decide).",
        "Explain how suggestions differ from flags: suggestions are always optional and never block submission. They appear as recommendations alongside your claim.",
        "Explain how to accept or dismiss suggestions, and that the engine learns from your choices over time.",
        "Cover the 'Review Recommended' tier: for complex or ambiguous scenarios, the platform provides a citation to the relevant SOMB section or Alberta Health resource rather than making a definitive recommendation.",
        "Cross-link to: [How the rules engine works](/help-centre/submitting-claims/how-the-rules-engine-works), [Understanding flags and suggestions on your claims](/help-centre/submitting-claims/understanding-flags-and-suggestions-on-your-claims)"
      ],
      [
        "Domain 7 Section 4: Tier 2 LLM Integration. Used for natural-language explanations, nuanced clinical-billing analysis, code alternative reasoning. Response processing: structured JSON, confidence scoring, hallucination guard. Fallback to Tier 1/3 if unavailable.",
        "Domain 7 Section 5: Tier 3 Review Recommended. Triggered by low confidence (<0.60), complex governing rules, novel code combinations. Provides physician with direct link to authoritative source. No suggested changes, no revenue impact, no confidence score.",
        "Domain 7 Section 6: Learning Loop. Acceptance rate, dismissal rate with reasons, rejection feedback. Frequently accepted suggestions maintain priority. Frequently dismissed suggestions demoted. Specialty cohort calibration for new physicians.",
        "Domain 7 Section 2: Suggestion Model. Priority: HIGH (>$20 impact or >80% rejection risk), MEDIUM ($5-$20 or 50-80%), LOW (<$5 or informational). Status lifecycle: presented, accepted, dismissed (with reason), expired."
      ]
    )
  ]
};

// ============================================================================
// SECTION 3: Tier 1 — Submission Cycle (1 task)
// ============================================================================
const section3 = {
  title: "Tier 1: Submission Cycle",
  tasks: [
    task("HC-014", "How the Thursday submission cycle works", "submitting-claims", "how-the-thursday-submission-cycle-works", "procedural", 1, "on-change", "300-600",
      [
        "**Content scope:** Explain the weekly Thursday submission cycle step by step.",
        "Cover the timeline:",
        "1. Throughout the week: create and validate claims, resolve flags, queue approved claims.",
        "2. Thursday 12:00 MT: cutoff. Claims queued by this time are included in this week's batch.",
        "3. Thursday 12:00-14:00: batch assembly. The platform groups claims by physician and BA number, runs final validation, generates H-Link files.",
        "4. Thursday afternoon: H-Link files transmitted to Alberta Health.",
        "5. Friday: assessment results arrive. Claims move to paid, held, or refused status.",
        "Explain the cutoff clearly: claims queued after 12:00 MT Thursday roll to the following week.",
        "Mention that physicians with PCPCM dual-BA setups will see two separate batches (one per BA).",
        "Cross-link to: [The Thursday submission cycle explained](/help-centre/billing-reference/the-thursday-submission-cycle-explained), [Your first Thursday submission](/help-centre/getting-started/your-first-thursday-submission)"
      ],
      [
        "Domain 4.1 Section 3: Thursday Batch Cycle. Thursday 12:00 MT cutoff, batch assembly (12:00-14:00), file generation, transmission, Friday assessment response, Friday payment. Batch assembly rules: grouping by physician + BA number, clean/flagged logic per auto-submission mode, final pre-submission validation.",
        "Domain 4.1 Section 4: H-Link File Generation. H-Link file structure: header, claim records, trailer. Transmission method: SFTP/API determined during accreditation.",
        "Domain 5 Section 7.2: PCPCM Batch Assembly Impact. PCPCM physicians generate two separate AHCIP batches per Thursday cycle: one for in-basket claims (PCPCM BA), one for out-of-basket claims (FFS BA)."
      ]
    )
  ]
};

// ============================================================================
// SECTION 4: Tier 2 — Submitting Claims Remaining (2 tasks)
// ============================================================================
const section4 = {
  title: "Tier 2: Submitting Claims Remaining",
  tasks: [
    task("HC-015", "Submission preferences explained", "submitting-claims", "submission-preferences-explained", "reference", 2, "on-change", "600-1000",
      [
        "**Content scope:** Detailed explanation of the three submission preference modes and when to use each.",
        "Cover each mode in depth:",
        "1. **Require Approval**: Every claim must be individually approved before it enters a batch. Best for physicians who want to review every claim before submission. This is the default.",
        "2. **Auto-submit clean**: Claims that pass all validation checks with no flags are automatically queued for the next Thursday batch. Flagged claims still require manual review. Best for most physicians: saves time on routine claims while catching potential issues.",
        "3. **Auto-submit all**: All claims (clean and flagged) are automatically queued. Flagged claims are submitted with their warnings. Use with caution: flagged claims may be rejected.",
        "Explain that AHCIP and WCB preferences are set independently.",
        "Explain how to change preferences (settings page, or during onboarding).",
        "Cover the interaction with the Thursday cycle: what happens if you change preferences mid-week.",
        "Cross-link to: [Choosing your submission preferences](/help-centre/getting-started/choosing-your-submission-preferences), [How the Thursday submission cycle works](/help-centre/submitting-claims/how-the-thursday-submission-cycle-works)"
      ],
      [
        "Domain 5 Section 2.7: Submission Preferences table. One row per physician. ahcip_mode and wcb_mode stored independently. Referenced by batch assembly process (Domain 4.0).",
        "Domain 4.0 Section 2: Claim State Machine. Tiered auto-submission model: Auto Clean (clean claims auto-queue, flagged held), Auto All (all claims auto-queue), Require Approval (manual approval for all). Clean = no errors or warnings. Flagged = has warnings or errors.",
        "Domain 4.1 Section 3: Thursday Batch Cycle. Batch assembly respects submission preferences when deciding which claims to include."
      ]
    ),

    task("HC-016", "Submitting WCB claims", "submitting-claims", "submitting-wcb-claims", "procedural", 2, "on-change", "300-600",
      [
        "**Content scope:** Explain how WCB claim submission differs from AHCIP.",
        "Cover: WCB uses specific form types (C050E for initial reports, C151 for progress reports, C568 for consultations, C570 for invoices), not the Thursday batch cycle.",
        "Explain the timing tiers: WCB fees vary based on how quickly you submit after the encounter (same-day, next-day, 2-5 days, 6-14 days, 15+ days). Earlier submission means higher fees.",
        "Explain the current MVP workflow: Meritum generates the WCB HL7 XML batch file for you to download and upload to the myWCB portal. Direct submission is planned for Phase 2.",
        "Cover the return file process: after uploading to myWCB, you receive a return file that you upload back to Meritum to match results to claims.",
        "Cross-link to: [WCB Alberta billing for physicians](/help-centre/billing-reference/wcb-alberta-billing-for-physicians), [Setting up WCB billing](/help-centre/getting-started/setting-up-wcb-billing)"
      ],
      [
        "Domain 4.2 Section 1: WCB Electronic Injury Reporting pathway. 8 form types (C050E, C050S, C151, C151S, C568, C568A, C569, C570). HL7 v2.3.1 XML batch submission.",
        "Domain 4.2 Section 5: WCB Submission Pipeline. Capture (guided form) → validate → queue → batch assembly → HL7 XML generation → XSD validation → download → manual upload to myWCB portal → return file processing → remittance reconciliation.",
        "Domain 4.2 Section 4: WCB Validation Engine. Timing deadline calculations: same-day, next-day, 2-5 day, 6-14 day, 15+ day tiers with fee impacts. Business day logic with 10 statutory holidays.",
        "Domain 4.2 Section 8: WCB Fee Calculation. Timing-based tiers with specific fee amounts per form type. Earlier submission = higher fee."
      ]
    )
  ]
};

// ============================================================================
// SECTION 5: Tier 2 — After Submission (4 tasks, skip PCPCM reconciliation)
// ============================================================================
const section5 = {
  title: "Tier 2: After Submission",
  tasks: [
    task("HC-017", "Understanding your assessment results", "after-submission", "understanding-your-assessment-results", "procedural", 2, "on-change", "300-600",
      [
        "**Content scope:** Explain what happens after claims are submitted and how to read assessment results.",
        "Cover the three possible outcomes: paid (claim accepted, payment issued), held (claim under review, awaiting further information), refused (claim rejected with an explanatory code).",
        "Explain where to find assessment results in the platform (dashboard, claim detail view).",
        "Explain the timing: AHCIP assessment results typically arrive Friday after a Thursday submission. WCB return files arrive after upload to myWCB.",
        "Cover adjusted claims: sometimes Alberta Health pays a different amount than submitted (e.g., fee reduced due to governing rule).",
        "Cross-link to: [Reading rejection codes](/help-centre/after-submission/reading-rejection-codes), [Correcting and resubmitting refused claims](/help-centre/after-submission/correcting-and-resubmitting-refused-claims)"
      ],
      [
        "Domain 4.1 Section 7: Assessment Response Ingestion. Friday assessment file retrieval from H-Link. Claim matching by submission reference. State transitions: accepted → assessed, rejected, adjusted. Explanatory code resolution from Reference Data. Notifications triggered.",
        "Domain 4.0 Section 2: Claim State Machine. Post-submission states: submitted → assessed (paid), rejected, adjusted. Each transition logged in claim audit history."
      ]
    ),

    task("HC-018", "Reading rejection codes", "after-submission", "reading-rejection-codes", "reference", 2, "on-change", "600-1000",
      [
        "**Content scope:** Help physicians understand AHCIP explanatory codes attached to refused or adjusted claims.",
        "Explain what explanatory codes are: codes from Alberta Health that explain why a claim was refused, held, or adjusted.",
        "Cover common explanatory code categories: claim errors (missing/invalid fields), governing rule violations (visit limits, referral requirements), payment adjustments (fee reduced), and administrative issues.",
        "For each common code category, explain in plain language what it means and what to do about it.",
        "Explain that Meritum provides plain-language explanations and corrective guidance for each code.",
        "Do NOT reproduce the full explanatory code list (copyrighted). Instead, explain how to read them and where to find the official reference.",
        "Cross-link to: [Common AHCIP explanatory codes and what they mean](/help-centre/billing-reference/common-ahcip-explanatory-codes-and-what-they-mean), [Correcting and resubmitting refused claims](/help-centre/after-submission/correcting-and-resubmitting-refused-claims)"
      ],
      [
        "Domain 2 Section 2: Explanatory Codes reference data set. Fields: code, category (claim_error, governing_rule, payment_adjustment, administrative), description, corrective_guidance (Meritum-authored plain-language), one_click_action, help_text.",
        "Domain 4.1 Section 5: AHCIP Validation Rules. 19 checks (A1-A19) that the rules engine applies pre-submission to prevent rejections. The explanatory codes on refused claims often correspond to these validation checks.",
        "Domain 4.1 Section 7: Assessment Response Ingestion. Explanatory code resolution: when an assessment includes an explanatory code, the platform looks up the code in Reference Data and displays the plain-language explanation and corrective guidance."
      ]
    ),

    task("HC-019", "Correcting and resubmitting refused claims", "after-submission", "correcting-and-resubmitting-refused-claims", "procedural", 2, "on-change", "300-600",
      [
        "**Content scope:** Walk through the process of correcting a refused claim and resubmitting it.",
        "Cover: how to find refused claims (filtered view on dashboard), how to read the rejection reason (explanatory code with plain-language explanation), how to edit the claim to fix the issue, and how to requeue it for the next Thursday batch.",
        "Explain the 90-day submission window: AHCIP claims must be submitted within 90 days of the date of service. If a refused claim is approaching this deadline, the platform flags it as urgent.",
        "Cover the resubmission workflow: edit claim → re-validate → queue → next Thursday batch.",
        "Mention that the platform tracks which claims have been resubmitted and their resolution history.",
        "Cross-link to: [Reading rejection codes](/help-centre/after-submission/reading-rejection-codes), [Tracking rejection patterns](/help-centre/after-submission/tracking-rejection-patterns)"
      ],
      [
        "Domain 4.0 Section 5: User Stories CLM-010. Rejection states and resubmission flow. Physician views refused claim, reads explanatory code, corrects fields, requeues for next batch.",
        "Domain 4.0 Section 2: Claim State Machine. Rejected claims can transition back to draft for editing, then through validated → queued → submitted again.",
        "Domain 4.1 Section 5: AHCIP Validation Rule A17. 90-day submission window check. Claims approaching deadline flagged with increasing urgency."
      ]
    ),

    task("HC-020", "Tracking rejection patterns", "after-submission", "tracking-rejection-patterns", "procedural", 2, "on-change", "300-600",
      [
        "**Content scope:** Explain how the analytics dashboard helps physicians identify and fix recurring rejection issues.",
        "Cover the Rejection Analysis dashboard: rejection rate trend, top rejection codes (with revenue impact), rejections by HSC code, rejection resolution funnel.",
        "Explain what to look for: recurring rejection codes (same issue happening repeatedly), high-value rejections (codes with significant revenue impact), and unresolved rejections (refused claims not yet corrected).",
        "Explain the corrective action effectiveness metric: does fixing the issue actually reduce future rejections?",
        "Mention the weekly rejection alert digest: if you have new rejections, the platform sends a summary.",
        "Cross-link to: [Reading rejection codes](/help-centre/after-submission/reading-rejection-codes), [Correcting and resubmitting refused claims](/help-centre/after-submission/correcting-and-resubmitting-refused-claims)"
      ],
      [
        "Domain 8 Section 2: Dashboard Specifications. Rejection Analysis dashboard: rejection rate trend, top rejection codes with revenue lost, rejection by HSC code, rejection resolution funnel, corrective action effectiveness, rejection heatmap.",
        "Domain 8 Section 6: Scheduled Reports. Rejection Alert Digest: daily if any new rejections, with codes and guidance. Weekly Billing Summary includes rejection rate.",
        "Domain 8 Section 3: Period Selection & Filtering. Time periods and filters for drilling into rejection data."
      ]
    )
  ]
};

// ============================================================================
// SECTION 6: Tier 2 — Your Account (8 tasks)
// ============================================================================
const section6 = {
  title: "Tier 2: Your Account",
  tasks: [
    task("HC-021", "Understanding your subscription", "your-account", "understanding-your-subscription", "reference", 2, "annual", "600-1000",
      [
        "**Content scope:** Explain subscription tiers, what is included, and billing details.",
        "Cover the subscription options: Standard monthly ($279/month), Standard annual ($2,790/year, ~17% savings), Early bird monthly ($199/month for first 100 physicians, first 12 months).",
        "Explain what is included: full platform access, all claim submission pathways (AHCIP and WCB), rules engine and advice engine, analytics dashboards, data export, help centre access.",
        "Cover GST: 5% GST is added to all prices (Meritum is a Canadian company).",
        "Explain the trial period if applicable.",
        "Do not use competitive comparisons or sales language. State the facts plainly.",
        "Cross-link to: [Switching between monthly and annual billing](/help-centre/your-account/switching-between-monthly-and-annual-billing), [Cancelling your subscription](/help-centre/your-account/cancelling-your-subscription)"
      ],
      [
        "Domain 12 Section 2: Stripe Integration. Pricing: Standard monthly $279, Standard annual $2,790 (~17% savings), Early bird monthly $199 (first 100 physicians, first 12 months). GST 5% added. CAD only. Credit card via Stripe.",
        "Domain 12 Section 3: Subscription Lifecycle. States: TRIAL (full access, no payment), ACTIVE (payment current, full access), PAST_DUE (payment failed, full access during dunning), SUSPENDED (read-only), CANCELLED (30-day grace for export)."
      ]
    ),

    task("HC-022", "Switching between monthly and annual billing", "your-account", "switching-between-monthly-and-annual-billing", "procedural", 2, "annual", "300-600",
      [
        "**Content scope:** Explain how to switch billing frequency.",
        "Cover: how to access billing settings (via Stripe Customer Portal link in account settings), what happens when you switch (proration handled by Stripe), when the new billing cycle starts.",
        "Explain annual savings: annual billing saves approximately 17% compared to monthly.",
        "Note that early bird pricing is only available as monthly billing for the first 12 months.",
        "Cross-link to: [Understanding your subscription](/help-centre/your-account/understanding-your-subscription)"
      ],
      [
        "Domain 12 Section 2: Stripe Integration. Customer Portal: Stripe-hosted UI for update payment, view invoices, switch monthly/annual, cancel subscription. Accessed via Meritum account settings button. Webhooks sync changes back to Meritum.",
        "Domain 12 Section 9: User Stories PLT-007. Switch monthly to annual: via Customer Portal, proration handled by Stripe, Meritum updates plan on webhook."
      ]
    ),

    task("HC-023", "Managing your practice account", "your-account", "managing-your-practice-account", "procedural", 2, "annual", "300-600",
      [
        "**Content scope:** Explain the practice admin role and what they can manage.",
        "Cover: what the admin dashboard shows, what actions the admin can take (add/remove physicians in a practice group), what the admin cannot see (individual physician PHI without consent).",
        "Explain the scope of admin access: admin has all permissions plus ADMIN_PHI_ACCESS, but PHI access requires explicit physician consent and is logged.",
        "This article addresses practice groups, not individual physician accounts.",
        "Cross-link to: [Practice admin access boundaries](/help-centre/security-compliance/practice-admin-access-boundaries)"
      ],
      [
        "Domain 1 Section 2: Roles & Permissions. Admin role: platform ops, all permissions plus ADMIN_PHI_ACCESS. No PHI access without physician consent.",
        "Domain 12 Section 1: Platform Operations overview. Admin-facing operational dashboards, user activity metrics."
      ]
    ),

    task("HC-024", "The referral program", "your-account", "the-referral-program", "reference", 2, "annual", "600-1000",
      [
        "**Content scope:** Explain how the referral program works.",
        "Cover: how referrals work (referring physician gets $50 credit when referred physician completes onboarding and pays first month), eligibility (any active subscriber), where credits are applied (next invoice as Stripe balance adjustment, no cash payouts), referral code (unique per physician, entered at registration).",
        "Cover limits: maximum 10 credits per physician per year ($500 cap).",
        "Explain how referral credits interact with the clinic tier (if applicable).",
        "Note: the referral program launches post-PMF (product-market fit). State current availability clearly.",
        "Cross-link to: [Understanding your subscription](/help-centre/your-account/understanding-your-subscription)"
      ],
      [
        "Domain 12 Section 7: Referral Program (Post-PMF). Referring physician gets $50 credit on next invoice when referred physician completes onboarding + pays first month. Stripe balance adjustments (negative line items, no cash payouts). Referral codes per physician. Max 10 credits/physician/year ($500 cap). MVP: referral code field hidden/disabled, tracking table defined not populated."
      ]
    ),

    task("HC-025", "Cancelling your subscription", "your-account", "cancelling-your-subscription", "procedural", 2, "annual", "300-600",
      [
        "**Content scope:** Explain the cancellation process and what happens to your data.",
        "Cover: how to cancel (via account settings or Stripe Customer Portal), what happens immediately (subscription marked cancelled), the 30-day grace period (read-only access, data export available).",
        "Explain the data retention timeline: after cancellation, you have 30 days to export your data. After 30 days, PHI is permanently deleted. Audit logs are retained for 10 years per HIA requirements (with PII stripped). IMA records retained 10 years.",
        "Cover monthly vs annual cancellation: monthly cancels at end of current period, annual may have different refund terms.",
        "Cross-link to: [Exporting your data](/help-centre/your-account/exporting-your-data)"
      ],
      [
        "Domain 12 Section 4: Account Deletion. Request from settings → confirmation dialog → type 'DELETE' → subscription cancelled immediately → 30-day grace (read-only + data portability) → reminders Day 7 + Day 21 → after 30 days all PHI deleted. Audit logs retained 10 years HIA with PII stripped. IMA records retained 10 years.",
        "Domain 12 Section 3: Subscription Lifecycle. CANCELLED state: 30-day grace for export, then data deletion."
      ]
    ),

    task("HC-026", "Exporting your data", "your-account", "exporting-your-data", "procedural", 2, "annual", "300-600",
      [
        "**Content scope:** Explain the data export (data portability) feature.",
        "Cover: what is included in the export (all claims in all states, all patients, claim audit history, billing suggestions, batch history, provider profile), the export format (ZIP archive with CSV files + JSON + README schema), how to request an export, the download process (authenticated link, 72-hour expiry, optional password encryption).",
        "Explain the 30-day availability window after cancellation.",
        "Mention the accountant export as a separate, more focused export option for tax/accounting purposes.",
        "Cross-link to: [Cancelling your subscription](/help-centre/your-account/cancelling-your-subscription)"
      ],
      [
        "Domain 8 Section 5: Data Portability Export. HIA-compliant complete data export: all claims, all patients, claim audit history, AI Coach suggestions, batch history, provider profile. ZIP archive with CSV + JSON + README. Asynchronous generation, authenticated download link (72-hour expiry), optional password encryption, audit-logged.",
        "Domain 8 Section 4: Accountant Export. Separate focused export: CSV (machine-readable), PDF Summary (monthly/annual), PDF Detailed (per-claim). Monthly scheduled on 3rd business day."
      ]
    ),

    task("HC-027", "Updating your profile", "your-account", "updating-your-profile", "procedural", 2, "on-change", "300-600",
      [
        "**Content scope:** Explain how to update your professional profile after initial onboarding.",
        "Cover: specialty changes (what triggers re-validation, how it affects code availability), adding/removing practice locations, BA changes (adding a new BA, changing submitter role), WCB contract changes.",
        "Address edge cases from the content brief Section 2.1:",
        "- Specialty changes mid-subscription: does not affect historical claim data; may change SOMB code availability in search; no re-confirmation of BA required.",
        "- BA additions: adding a PCPCM BA alongside an existing FFS BA triggers the dual-BA setup flow.",
        "- Locum location changes: add new locations as needed, set default appropriately.",
        "Cross-link to: [Setting up your professional profile](/help-centre/getting-started/setting-up-your-professional-profile), [Adding your business arrangement numbers](/help-centre/getting-started/adding-your-business-arrangement-numbers)"
      ],
      [
        "Domain 5 Section 4.3: Ongoing Management user stories. Profile updates, BA additions/removals, location changes, WCB contract changes.",
        "Domain 5 Section 2: Data Model. Providers table (specialty_code, physician_type), Business Arrangements (max 2 active, PCPCM dual-BA), Practice Locations (multi-site, locum), WCB Configurations (multiple Contract IDs).",
        "Content Brief Section 2.1: Edge cases. Specialty changes mid-subscription, BA changes and additions, locum-specific setup, WCB contract changes."
      ]
    ),

    task("HC-028", "Managing delegates", "your-account", "managing-delegates", "procedural", 2, "on-change", "300-600",
      [
        "**Content scope:** Explain ongoing delegate management after the initial invitation.",
        "Cover: changing a delegate's permissions (immediate effect), revoking delegate access (immediate session invalidation), adding new delegates.",
        "Address the delegate handover scenario from content brief Section 2.1: when a delegate leaves and a new one takes over, the physician should revoke the old delegate's access and invite the new one. There is no 'transfer' function; it is a remove-and-add process.",
        "Explain multi-physician delegation from the delegate's perspective: a delegate serving multiple physicians has independent permissions for each.",
        "Cross-link to: [Inviting a delegate](/help-centre/getting-started/inviting-a-delegate), [Delegate access and data separation](/help-centre/security-compliance/delegate-access-and-data-separation)"
      ],
      [
        "Domain 1 Section 3: User Stories IAM-008 Delegate Permission Modification (toggle permissions, immediate effect, audit logged). IAM-009 Delegate Removal (immediate session invalidation for this physician, other physicians unaffected, notification to delegate).",
        "Domain 5 Section 3: Delegate Permission Model. Permission catalogue, preset templates, granular configuration. Permission changes audit-logged and take effect immediately.",
        "Domain 5 Section 3.3: Multi-Physician Delegation. Each physician-delegate relationship has its own independent permission set. Context switching is explicit and logged."
      ]
    )
  ]
};

// ============================================================================
// SECTION 7: Tier 3 — Alberta Billing Reference (10 tasks)
// ============================================================================
const section7 = {
  title: "Tier 3: Alberta Billing Reference",
  tasks: [
    task("HC-029", "AHCIP fee-for-service billing: how the system works", "billing-reference", "ahcip-fee-for-service-billing-how-the-system-works", "reference", 3, "quarterly", "600-1000",
      [
        "**Content scope:** Overview of AHCIP fee-for-service billing for physicians new to self-billing.",
        "Cover: what AHCIP is (Alberta Health Care Insurance Plan, the provincial health insurance program), how FFS billing works (physician submits claims for each insured service, Alberta Health pays per the SOMB fee schedule), the role of HSC codes (Health Service Codes from the SOMB), what a BA number is, how electronic submission works (via H-Link).",
        "This is a foundational reference article. Write for a physician who may be new to billing their own claims (e.g., transitioning from a clinic that handled billing for them).",
        "Do not reproduce fee amounts or rate tables. Explain the system and link to official sources.",
        "Cross-link to: [The Thursday submission cycle explained](/help-centre/billing-reference/the-thursday-submission-cycle-explained), [Understanding the Schedule of Medical Benefits](/help-centre/billing-reference/understanding-the-schedule-of-medical-benefits), [H-Link: what it is and how electronic claims submission works](/help-centre/billing-reference/h-link-what-it-is-and-how-electronic-claims-submission-works)"
      ],
      [
        "Domain 4.1 Section 1: AHCIP Claim Pathway overview. AHCIP-specific submission via H-Link. Weekly Thursday batch cycle. Fee calculation: base fee + modifiers + premiums.",
        "Domain 4.1 Section 2: AHCIP Claim Data Elements. BA number, functional centre, HSC code, modifiers, diagnostic code, facility number, referral practitioner.",
        "Domain 2 Section 2: SOMB Fee Schedule. ~6,000+ HSC records. Fields: hsc_code, description, base_fee, fee_type, specialty_restrictions, modifier_eligibility."
      ]
    ),

    task("HC-030", "The Thursday submission cycle explained", "billing-reference", "the-thursday-submission-cycle-explained", "reference", 3, "quarterly", "600-1000",
      [
        "**Content scope:** Detailed reference explaining Alberta Health's weekly AHCIP processing schedule.",
        "Cover: why Thursday (Alberta Health processes claims weekly), the full timeline (physician submits by Thursday, Alberta Health processes, assessment results returned Friday, payment follows), how electronic submission works via accredited submitters and H-Link.",
        "Explain what happens behind the scenes: batch files are assembled, transmitted via H-Link, Alberta Health validates against SOMB rules, returns assessment results.",
        "This is the reference version aimed at any Alberta physician. The procedural version (Category 2) focuses on Meritum-specific steps.",
        "Do not reproduce proprietary Alberta Health processing details. Explain what is publicly known about the weekly cycle.",
        "Cross-link to: [How the Thursday submission cycle works](/help-centre/submitting-claims/how-the-thursday-submission-cycle-works), [H-Link: what it is and how electronic claims submission works](/help-centre/billing-reference/h-link-what-it-is-and-how-electronic-claims-submission-works)"
      ],
      [
        "Domain 4.1 Section 3: Thursday Batch Cycle. Thursday 12:00 MT cutoff, batch assembly, file generation, H-Link transmission. Friday assessment file retrieval.",
        "Domain 4.1 Section 4: H-Link File Generation. H-Link file structure per Electronic Claims Submission Specifications Manual. Header, claim records, trailer. Transmission via SFTP/API.",
        "Domain 4.1 Section 7: Assessment Response Ingestion. Friday file retrieval, parsing, claim matching, state transitions, explanatory code resolution."
      ]
    ),

    task("HC-031", "Understanding the Schedule of Medical Benefits", "billing-reference", "understanding-the-schedule-of-medical-benefits", "reference", 3, "quarterly", "600-1000",
      [
        "**Content scope:** Explain the SOMB structure and how physicians use it.",
        "Cover: what the SOMB is (the fee schedule published by Alberta Health listing all insured health services and their fees), how it is structured (HSC codes organized by section/specialty), how to look up a code, what governing rules are (rules that constrain when and how codes can be billed), how modifiers work (adjustments to the base fee).",
        "Explain that the SOMB is updated quarterly (April, July, October, January) plus mid-quarter bulletins.",
        "Explain that Meritum embeds the SOMB data and keeps it current, so physicians search codes within the platform rather than consulting the PDF.",
        "Do not reproduce rate tables or specific fee amounts.",
        "Cross-link to: [After-hours billing and time premiums](/help-centre/billing-reference/after-hours-billing-and-time-premiums), [Common AHCIP explanatory codes](/help-centre/billing-reference/common-ahcip-explanatory-codes-and-what-they-mean)"
      ],
      [
        "Domain 2 Section 2: SOMB Fee Schedule. Source: Alberta Health PDF + bulletins. Quarterly updates Apr/Jul/Oct/Jan + mid-quarter. ~6,000+ HSC records. Fields: hsc_code, description, base_fee, fee_type, specialty_restrictions, facility_restrictions, max_per_day, requires_referral, modifier_eligibility, pcpcm_basket, help_text.",
        "Domain 2 Section 2: Governing Rules. Source: SOMB Preamble + GR section. Key rules: GR 1 General, GR 3 Visit Limits, GR 5 DI, GR 8 Referrals, GR 10 Surgical, GR 14 Obstetric, GR 18 Chronic Disease Management.",
        "Domain 2 Section 2: Modifier Definitions. Types: explicit, implicit, semi_implicit. Calculation methods: percentage, fixed, time-based, multiplier. MVP modifiers: CMGP, LSCD, AFHR, BCP, RRNP, TM, ANE."
      ]
    ),

    task("HC-032", "RRNP: Rural and Remote Northern Program", "billing-reference", "rrnp-rural-and-remote-northern-program", "reference", 3, "quarterly", "600-1000",
      [
        "**Content scope:** Explain the RRNP for physicians practising in rural or remote Alberta communities.",
        "Cover: what the RRNP is (a premium added to AHCIP fee-for-service claims for physicians practising in eligible communities), eligibility criteria (based on community code, not physician residence), the premium range (7% to 30%+ depending on community), how it is calculated (applied to base fee), annual updates.",
        "Explain that Meritum automatically calculates the RRNP premium based on the community code of your practice location.",
        "Do not reproduce the full community rate table. Explain how to check eligibility and link to the official Alberta Health source.",
        "Cross-link to: [Configuring your practice locations](/help-centre/getting-started/configuring-your-practice-locations)"
      ],
      [
        "Domain 2 Section 2: RRNP Community Rate Table. Source: Alberta Health Rural Remote Northern Program. Annual updates. Fields: community_code, community_name, rrnp_percentage (7%-30%+), effective_from/to.",
        "Domain 5 Section 2.3: Practice Locations. Community_code validated against Reference Data. RRNP eligibility determined by community code of practice location.",
        "Domain 4.1 Section 6: AHCIP Fee Calculation. RRNP premium calculation: applied as percentage addition to base fee for eligible community codes."
      ]
    ),

    task("HC-033", "PCPCM: Primary Care Panel and Continuity Model", "billing-reference", "pcpcm-primary-care-panel-and-continuity-model", "reference", 3, "quarterly", "600-1000",
      [
        "**Content scope:** Explain the PCPCM for primary care physicians.",
        "Cover: what PCPCM is (a blended funding model combining capitation payments with FFS billing), how it differs from pure FFS (enrolled patients generate capitation payments; FFS claims are still submitted for services), the dual-BA requirement (physicians need both a PCPCM BA and a FFS BA), how claim routing works (in-basket codes route to PCPCM BA, out-of-basket codes route to FFS BA).",
        "Explain panel enrolment tracking and the concept of basket classification (which HSC codes are covered by the capitation payment vs billed separately).",
        "Do not reproduce specific capitation rates or basket classification tables.",
        "Cross-link to: [Adding your business arrangement numbers](/help-centre/getting-started/adding-your-business-arrangement-numbers)"
      ],
      [
        "Domain 5 Section 7: PCPCM Routing Logic. Dual-BA arrangement. Routing: look up HSC code's basket classification in Reference Data. In-basket → PCPCM BA. Out-of-basket → FFS BA. Routing decided at claim creation time, stored on AHCIP claim detail.",
        "Domain 5 Section 7.2: Batch Assembly Impact. PCPCM physicians generate two separate batches per Thursday cycle: in-basket (PCPCM BA) and out-of-basket (FFS BA).",
        "Domain 5 Section 2.4: PCPCM Enrolment table. Tracks enrolment details for PCPCM physicians. Only applicable to physicians with PCPCM-type BA.",
        "Domain 2 Section 2: PCPCM Basket Classification. hsc_code, basket (in_basket / out_of_basket / facility). Determines BA routing. Version-aware (DOS governs)."
      ]
    ),

    task("HC-034", "WCB Alberta billing for physicians", "billing-reference", "wcb-alberta-billing-for-physicians", "reference", 3, "quarterly", "600-1000",
      [
        "**Content scope:** Reference article explaining how WCB billing works in Alberta for physicians.",
        "Cover: what WCB billing is (separate from AHCIP; physicians bill WCB directly for treating workplace injuries), contract types and role codes, the 8 form types and when each is used (C050E initial report, C151 progress, C568 consultation, C570 invoice, etc.), how WCB differs from AHCIP (no Thursday cycle, timing-based fee tiers, different submission pathway).",
        "Explain timing tiers: WCB reimburses at different rates depending on how quickly the physician submits after seeing the patient. Same-day submission earns the highest fee; delayed submission earns less.",
        "Do not reproduce WCB fee schedules or specific rates.",
        "Cross-link to: [Setting up WCB billing](/help-centre/getting-started/setting-up-wcb-billing), [Submitting WCB claims](/help-centre/submitting-claims/submitting-wcb-claims)"
      ],
      [
        "Domain 4.2 Section 1: WCB overview. Electronic Injury Reporting (EIR) pathway. 8 form types. HL7 v2.3.1 XML batch submission. Return file processing. Payment remittance reconciliation.",
        "Domain 4.2 Section 2: WCB Form Types. C050E (initial report), C050S (specialist initial), C151 (progress), C151S (specialist progress), C568 (consultation), C568A (amendment), C569 (equipment/supplies), C570 (invoice/correction). Contract ID/Role/Form ID permission matrix.",
        "Domain 4.2 Section 8: WCB Fee Calculation. Timing-based tiers: same-day, next-day, 2-5 day, 6-14 day, 15+ day. Earlier = higher fee. 351 premium for operative encounters. Unbundling: WCB 100% unbundled (no combination reductions)."
      ]
    ),

    task("HC-035", "After-hours billing and time premiums", "billing-reference", "after-hours-billing-and-time-premiums", "reference", 3, "quarterly", "600-1000",
      [
        "**Content scope:** Explain after-hours billing modifiers and time-based premiums in AHCIP.",
        "Cover: the AFHR modifier (after-hours premium), time-period definitions (evening 17:00-23:00, night 23:00-08:00, weekends, statutory holidays), the 03.01AA code reference, how the premium is calculated (percentage of base fee), which codes are eligible.",
        "Explain time-based modifiers (CMGP for time-based counselling/management) and how time documentation requirements work.",
        "Cover the 10 Alberta statutory holidays relevant to after-hours calculations.",
        "Do not reproduce specific premium percentages or fee amounts.",
        "Cross-link to: [Understanding the Schedule of Medical Benefits](/help-centre/billing-reference/understanding-the-schedule-of-medical-benefits)"
      ],
      [
        "Domain 2 Section 2: Modifier Definitions. AFHR: percentage premium, auto time-based, stat holiday aware (GR 6). CMGP: time-based units (GR 6). LSCD: prolonged add-on, requires CMGP.",
        "Domain 2 Section 2: Alberta Statutory Holiday Calendar. 10 holidays: New Year's, Family Day, Good Friday, Victoria Day, Canada Day, Heritage Day, Labour Day, Truth and Reconciliation, Thanksgiving, Remembrance Day, Christmas.",
        "Domain 4.1 Section 6: AHCIP Fee Calculation. After-hours calculation: evening, weekend, stat holiday premiums. Fee formula: submitted_fee = base_fee x calls + modifier_adjustments + premiums.",
        "Domain 10 Section 2: ED Shift Workflow. After-hours auto-detection: weekday evening 17:00-23:00 suggests AFHR, night 23:00-08:00 suggests NGHR, weekend/stat suggests WKND."
      ]
    ),

    task("HC-036", "Common AHCIP explanatory codes and what they mean", "billing-reference", "common-ahcip-explanatory-codes-and-what-they-mean", "reference", 3, "quarterly", "600-1000",
      [
        "**Content scope:** Plain-language reference for frequently encountered AHCIP explanatory codes.",
        "Cover common code categories with explanations:",
        "- Claim errors: missing or invalid fields (e.g., missing diagnostic code, invalid PHN format)",
        "- Governing rule violations: visit limits exceeded (GR 3), missing referral for specialist consultation (GR 8), modifier not eligible for this code",
        "- Payment adjustments: fee reduced due to governing rule, partial payment, bundling applied",
        "- Administrative: duplicate claim, claim already processed, provider not registered",
        "For each category, explain in plain language what the physician should do to resolve it.",
        "Do NOT reproduce the full Alberta Health explanatory code list (copyrighted). Explain common patterns and link to the official reference.",
        "Cross-link to: [Reading rejection codes](/help-centre/after-submission/reading-rejection-codes), [How the rules engine works](/help-centre/submitting-claims/how-the-rules-engine-works)"
      ],
      [
        "Domain 2 Section 2: Explanatory Codes. Categories: claim_error, governing_rule, payment_adjustment, administrative. Fields: code, category, description, corrective_guidance (Meritum-authored), one_click_action, help_text.",
        "Domain 4.1 Section 5: AHCIP Validation Rules A1-A19. These rules prevent the most common rejection reasons. Mapping: GR 3 visit limits, GR 8 referral requirements, GR 5 DI surcharge, modifier eligibility/conflicts, 90-day window.",
        "Domain 4.1 Section 7: Assessment Response Ingestion. Explanatory code resolution from Reference Data with plain-language explanations."
      ]
    ),

    task("HC-037", "Business arrangements in Alberta", "billing-reference", "business-arrangements-in-alberta", "reference", 3, "quarterly", "600-1000",
      [
        "**Content scope:** Explain what BA numbers are and how they work in Alberta.",
        "Cover: what a BA number is (identifies your billing arrangement with Alberta Health; determines where payment is deposited), contract holders vs submitter roles, how to set up a new BA (AHC11236 form), the PCPCM dual-BA arrangement.",
        "Explain the difference between the BA holder (the physician or corporation) and the submitter (the accredited entity that transmits claims electronically on behalf of the BA holder).",
        "Cover common scenarios: solo practitioner with one BA, physician with PCPCM dual-BA, locum billing under another physician's BA, physician changing practices and updating BA associations.",
        "Cross-link to: [Adding your business arrangement numbers](/help-centre/getting-started/adding-your-business-arrangement-numbers)"
      ],
      [
        "Domain 5 Section 2.2: Business Arrangements table. Max 2 active BAs per provider. Standard FFS: one BA. PCPCM: two BAs (PCPCM + FFS). ba_number unique across active records. BA types: FFS, PCPCM, LOCUM.",
        "Domain 11 Section 4: AHC11236 Form Pre-Fill. AHC11236 links BA to accredited submitter (Meritum). Physician downloads pre-filled PDF, signs, submits to Alberta Health. BA status tracking: PENDING → ACTIVE after Alberta Health processing (2-4 weeks).",
        "Domain 5 Section 8: Locum Support. Locum physicians may bill under another physician's BA or their own BA at different facilities."
      ]
    ),

    task("HC-038", "H-Link: what it is and how electronic claims submission works", "billing-reference", "h-link-what-it-is-and-how-electronic-claims-submission-works", "reference", 3, "quarterly", "600-1000",
      [
        "**Content scope:** Explain H-Link and the electronic claims submission infrastructure in Alberta.",
        "Cover: what H-Link is (Alberta Health's electronic claims submission system for AHCIP claims), how it works (accredited submitters transmit claim files, Alberta Health processes and returns assessment results), the role of accredited submitters (Meritum is an accredited submitter), the file format (claim records with header and trailer), security (encrypted transmission).",
        "Explain that physicians do not interact with H-Link directly; Meritum handles the electronic submission on their behalf.",
        "This is a reference article explaining the infrastructure. The procedural articles explain the Meritum-specific workflow.",
        "Cross-link to: [The Thursday submission cycle explained](/help-centre/billing-reference/the-thursday-submission-cycle-explained), [AHCIP fee-for-service billing](/help-centre/billing-reference/ahcip-fee-for-service-billing-how-the-system-works)"
      ],
      [
        "Domain 4.1 Section 4: H-Link File Generation. H-Link file structure per Electronic Claims Submission Specifications Manual: header, claim records, trailer. Field-to-HL7 mappings. Transmission method: SFTP/API determined during accreditation. Security: TLS 1.3, encrypted files. Retry logic on failure.",
        "Domain 4.1 Section 9: H-Link Security. Generated files encrypted at rest (AES-256), transmitted via secure channel, credentials in secrets management, all files contain PHI with Canadian data residency.",
        "Domain 5 Section 2.8: H-Link Configuration table. Stores physician's H-Link submission identity. Credentials are references to secrets management."
      ]
    )
  ]
};

// ============================================================================
// SECTION 8: Tier 3 — Security & Compliance (5 tasks)
// ============================================================================
const section8 = {
  title: "Tier 3: Security & Compliance",
  tasks: [
    task("HC-039", "How Meritum protects your data", "security-compliance", "how-meritum-protects-your-data", "reference", 3, "annual", "600-1000",
      [
        "**Content scope:** Explain Meritum's security measures in language accessible to physicians (not a security team).",
        "Cover: encryption at rest and in transit (AES-256, TLS 1.3), access controls (mandatory MFA, session management, role-based permissions), hosting (DigitalOcean Toronto, Canadian data residency), audit logging (every access logged), backup and recovery.",
        "Explain mandatory TOTP MFA: every user must set up two-factor authentication before accessing the platform.",
        "Cover session security: 24-hour absolute expiry, 60-minute idle expiry, remote session revocation.",
        "Write for a physician audience: focus on what protections are in place and what they mean in practice, not on technical implementation details.",
        "Cross-link to: [Canadian data residency](/help-centre/security-compliance/canadian-data-residency), [HIA compliance and the Information Manager Agreement](/help-centre/security-compliance/hia-compliance-and-the-information-manager-agreement)"
      ],
      [
        "Domain 1 Section 7: Security Requirements. Credential storage: passwords Argon2id, TOTP secrets AES-256-GCM encrypted, session tokens SHA-256 hashed. Transport: TLS 1.3, HSTS, HttpOnly Secure SameSite=Strict cookies. Rate limiting on login attempts.",
        "Domain 1 Section 3: IAM-002 Mandatory MFA Setup. TOTP QR code + manual key. 10 recovery codes shown once. IAM-006 Session Management: 24h absolute + 60min idle expiry, remote revocation, concurrent sessions allowed.",
        "Domain 12 Section 5: Status Page. System health monitoring: API availability 99.9% target, encrypted storage, Canadian data residency."
      ]
    ),

    task("HC-040", "HIA compliance and the Information Manager Agreement", "security-compliance", "hia-compliance-and-the-information-manager-agreement", "reference", 3, "annual", "600-1000",
      [
        "**Content scope:** Explain HIA compliance and what the IMA means for physicians.",
        "Cover: what the Health Information Act (HIA) is (Alberta's legislation governing the collection, use, and disclosure of health information), what Section 66 requires (Information Manager Agreement before a third party processes PHI on behalf of a custodian), what the IMA contains (data handling obligations, encryption, Canadian residency, breach notification, retention/disposal, termination provisions).",
        "Explain that the physician is the custodian of their patients' health information under HIA. Meritum is the Information Manager. The IMA formalises this relationship.",
        "Explain the IMA acknowledgement process during onboarding (digital acknowledgement, not a wet signature; timestamp + document hash stored).",
        "Mention the PIA (Privacy Impact Assessment) appendix available for download.",
        "Cross-link to: [How Meritum protects your data](/help-centre/security-compliance/how-meritum-protects-your-data), [Canadian data residency](/help-centre/security-compliance/canadian-data-residency)"
      ],
      [
        "Domain 11 Section 3: IMA Generation. HIA s.66 requires IMA before processing PHI. IMA content: pre-filled with physician details, Meritum corporate details, service description, data handling obligations (encryption, Canadian residency, breach notification, retention/disposal), termination provisions.",
        "Domain 11 Section 3: Digital Acknowledgement. Scrollable document viewer. 'I Acknowledge and Agree' button. Stored: ima_id, template_version, document_hash SHA-256, acknowledged_at, IP, user_agent. PIA appendix: downloadable PDF, no acknowledgement required.",
        "Domain 1 Section 7: Security Requirements. PHI isolation, encryption at rest/in transit, Canadian data residency, audit logging."
      ]
    ),

    task("HC-041", "Canadian data residency", "security-compliance", "canadian-data-residency", "reference", 3, "annual", "600-1000",
      [
        "**Content scope:** Explain what 'data stays in Canada' means in practice.",
        "Cover: where data is hosted (DigitalOcean Toronto data centre), what 'Canadian data residency' means (all PHI stored and processed within Canadian borders; no replication to US or other jurisdictions), why this matters under HIA (Alberta's Health Information Act requires that health information be stored in Canada unless specific conditions are met).",
        "Explain that Stripe (payment processing) receives only physician name and email for billing purposes; no patient data, claim data, or health information is sent to Stripe or any non-Canadian service.",
        "Cover the self-hosted AI: the advice engine's language model runs on Canadian infrastructure (DigitalOcean Toronto); no patient or claim data is sent to external AI services.",
        "Cross-link to: [How Meritum protects your data](/help-centre/security-compliance/how-meritum-protects-your-data), [HIA compliance and the Information Manager Agreement](/help-centre/security-compliance/hia-compliance-and-the-information-manager-agreement)"
      ],
      [
        "Domain 12 Section 2: Stripe Integration. PHI isolation: Stripe receives physician name + email only. No claim/patient/billing code data. Payment data separated from health data.",
        "Domain 7 Section 10: Security. Self-hosted LLM on DigitalOcean Toronto. No external API calls. Patient PHN/name stripped before analysis. Canadian data residency for all AI processing.",
        "Domain 1 Section 7: Security Requirements. Transport TLS 1.3. HSTS. All PHI encrypted at rest and in transit within Canadian infrastructure."
      ]
    ),

    task("HC-042", "Delegate access and data separation", "security-compliance", "delegate-access-and-data-separation", "reference", 3, "annual", "600-1000",
      [
        "**Content scope:** Explain how the platform enforces boundaries between physician data when delegates are involved.",
        "Cover: how delegate permissions work (each physician-delegate relationship has independent permissions), context switching (a delegate serving multiple physicians must explicitly switch between them; no cross-physician access in a single request), what delegates can and cannot see by default, how all delegate actions are logged with both the delegate's identity and the physician context.",
        "Explain that revoking a delegate immediately invalidates their sessions for that physician (other physician relationships are unaffected).",
        "Cover the batch approval authority: delegates with BATCH_APPROVE permission can approve flagged claims, but this is logged and the physician is notified.",
        "Cross-link to: [Inviting a delegate](/help-centre/getting-started/inviting-a-delegate), [Managing delegates](/help-centre/your-account/managing-delegates)"
      ],
      [
        "Domain 1 Section 2: Roles & Permissions. Delegate: configurable permissions per physician. Cannot access DELEGATE_MANAGE, SUBSCRIPTION_MANAGE, DATA_EXPORT, AUDIT_VIEW by default. IAM-010 Batch Approval Authority: specific permission, logged with delegate + physician context.",
        "Domain 5 Section 3.3: Multi-Physician Delegation. Independent permission sets per physician-delegate pair. Context switching explicit and logged. Cannot access data across physicians in a single request.",
        "Domain 1 Section 3: IAM-009 Delegate Removal. Immediate session invalidation for this physician. Other physician relationships unaffected. Notification to delegate."
      ]
    ),

    task("HC-043", "Practice admin access boundaries", "security-compliance", "practice-admin-access-boundaries", "reference", 3, "annual", "600-1000",
      [
        "**Content scope:** Explain what the practice admin can and cannot see, and why.",
        "Cover: what the admin role is (platform operations; manages the practice group), what the admin can do (view aggregate metrics, manage subscriptions, view system-wide audit logs), what the admin cannot do (access individual physician PHI without consent; the ADMIN_PHI_ACCESS permission requires explicit physician consent and is logged).",
        "Explain the design principle: administrative functions are separated from clinical data access. The admin sees operational data (who is active, subscription status, aggregate usage) but not patient-level or claim-level details.",
        "Explain that all admin actions are logged in the audit trail.",
        "Cross-link to: [Managing your practice account](/help-centre/your-account/managing-your-practice-account), [How Meritum protects your data](/help-centre/security-compliance/how-meritum-protects-your-data)"
      ],
      [
        "Domain 1 Section 2: Roles & Permissions. Admin: platform ops, all permissions plus ADMIN_PHI_ACCESS. No PHI access without physician consent. Admin panel: admin-only permission.",
        "Domain 1 Section 6: Audit Log Specification. Admins view system-wide audit logs (+ user ID, IP, action filters). Queries themselves logged.",
        "Domain 12 Section 1: Platform Operations. Admin-facing operational dashboards: platform health, user activity, business metrics. Not clinical data."
      ]
    )
  ]
};

// ============================================================================
// SECTION 9: Final Validation (1 task)
// ============================================================================
const section9 = {
  title: "Final Validation",
  tasks: [
    {
      id: "HC-099",
      description: "Validate all help centre articles: existence, cross-links, and total count",
      verify: "node scripts/validate-article.js help-centre/getting-started/setting-up-your-professional-profile.md",
      build: [
        "Run a comprehensive validation of all generated help centre articles.",
        "",
        "**Step 1: Verify all 43 articles exist.**",
        "Check that each of these files exists and is non-empty:",
        "",
        "getting-started/ (7 articles):",
        "- setting-up-your-professional-profile.md",
        "- adding-your-business-arrangement-numbers.md",
        "- configuring-your-practice-locations.md",
        "- setting-up-wcb-billing.md",
        "- inviting-a-delegate.md",
        "- choosing-your-submission-preferences.md",
        "- your-first-thursday-submission.md",
        "",
        "submitting-claims/ (9 articles):",
        "- importing-encounters-from-your-emr.md",
        "- using-mobile-claim-entry.md",
        "- creating-claims-manually.md",
        "- understanding-flags-and-suggestions-on-your-claims.md",
        "- how-the-rules-engine-works.md",
        "- how-the-advice-engine-works.md",
        "- how-the-thursday-submission-cycle-works.md",
        "- submission-preferences-explained.md",
        "- submitting-wcb-claims.md",
        "",
        "after-submission/ (4 articles):",
        "- understanding-your-assessment-results.md",
        "- reading-rejection-codes.md",
        "- correcting-and-resubmitting-refused-claims.md",
        "- tracking-rejection-patterns.md",
        "",
        "your-account/ (8 articles):",
        "- understanding-your-subscription.md",
        "- switching-between-monthly-and-annual-billing.md",
        "- managing-your-practice-account.md",
        "- the-referral-program.md",
        "- cancelling-your-subscription.md",
        "- exporting-your-data.md",
        "- updating-your-profile.md",
        "- managing-delegates.md",
        "",
        "billing-reference/ (10 articles):",
        "- ahcip-fee-for-service-billing-how-the-system-works.md",
        "- the-thursday-submission-cycle-explained.md",
        "- understanding-the-schedule-of-medical-benefits.md",
        "- rrnp-rural-and-remote-northern-program.md",
        "- pcpcm-primary-care-panel-and-continuity-model.md",
        "- wcb-alberta-billing-for-physicians.md",
        "- after-hours-billing-and-time-premiums.md",
        "- common-ahcip-explanatory-codes-and-what-they-mean.md",
        "- business-arrangements-in-alberta.md",
        "- h-link-what-it-is-and-how-electronic-claims-submission-works.md",
        "",
        "security-compliance/ (5 articles):",
        "- how-meritum-protects-your-data.md",
        "- hia-compliance-and-the-information-manager-agreement.md",
        "- canadian-data-residency.md",
        "- delegate-access-and-data-separation.md",
        "- practice-admin-access-boundaries.md",
        "",
        "**Step 2: Validate each article.**",
        "Run `node scripts/validate-article.js` on every article. All must pass.",
        "",
        "**Step 3: Check cross-links resolve.**",
        "Scan all articles for markdown links matching `/help-centre/`. For each link, verify that the target file exists on disk.",
        "",
        "**Step 4: Report.**",
        "Output a summary: total articles found, total validated, any missing articles, any broken cross-links, total word count across all articles.",
        "",
        "Write a validation script at `scripts/validate-all-articles.js` that performs all four steps. Run it and report the results."
      ],
      context: SHARED_CONTEXT,
      frd: [
        "Content Brief Section 8.4: Quality Checks. Front matter complete, no em dashes, no placeholder language, abbreviations spelled out, word count in range, cross-links resolve, no copyrighted rate tables."
      ]
    }
  ]
};

// ============================================================================
// Assemble the config
// ============================================================================
const config = {
  domainNumber: "HC",
  domainName: "Help Centre Content",
  manifestFile: "help-centre.tasks",
  promptPrefix: "hc",
  modulePath: "help-centre",
  sections: [section1, section2, section3, section4, section5, section6, section7, section8, section9]
};

fs.writeFileSync(outputPath, JSON.stringify(config, null, 2));
console.log(`Config written to: ${outputPath}`);

// Count tasks
let total = 0;
for (const s of config.sections) total += s.tasks.length;
console.log(`Total tasks: ${total}`);
console.log(`Sections: ${config.sections.length}`);
