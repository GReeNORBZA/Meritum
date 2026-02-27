---
title: "How the advice engine works"
category: submitting-claims
slug: how-the-advice-engine-works
description: "Explains how the advice engine analyses your claims and suggests billing optimisations such as modifier additions, code alternatives, and missed billing opportunities."
priority: 1
last_reviewed: 2026-02-25
review_cycle: on-change
type: reference
---

The advice engine analyses your claims after the rules engine finishes validation and recommends billing optimisations you may have missed. Unlike rules engine flags, advice engine suggestions are always optional: they never block submission and they never modify your claim without your approval.

## How the advice engine differs from the rules engine

The rules engine checks whether your claim meets Alberta Health Care Insurance Plan (AHCIP) structural requirements and Schedule of Medical Benefits (SOMB) governing rules. It catches errors that would cause rejection. The advice engine works after that step. It looks at the validated claim and asks a different question: could this claim be billed more effectively?

Suggestions appear in a separate panel below rules engine flags on the claim detail page. They are recommendations, not requirements. You can submit your claim without reviewing them and nothing changes about how the claim is processed.

## Suggestion categories

The advice engine generates suggestions in four categories.

**Modifier additions.** The engine identifies modifiers you are eligible to apply but have not included on the claim. For example, if you bill an office visit code that qualifies for the Comprehensive General Practitioner Modifier (CMGP) and your provider profile confirms you are enrolled, the engine suggests adding it. The suggestion includes the estimated reimbursement difference so you can judge whether it is worth applying.

**Code alternatives.** The engine compares your selected health service code (HSC) against similar codes that may better describe the documented service. In some cases, the alternative code carries a higher fee. The suggestion explains why the alternative might apply and what distinguishes it from your current selection. You make the final call; the engine does not change your code.

**Missed billing opportunities.** The engine reviews patterns in your recent claims and flags services you may have performed but not billed. For example, if you regularly bill a follow-up visit alongside a specific procedure for the same patient and this time you only billed the procedure, the engine notes the gap. This category draws on your own billing history, not a generic template.

**Review recommended.** Some scenarios are too complex or ambiguous for the engine to offer a specific recommendation. When this happens, the suggestion provides a direct citation to the relevant SOMB section or Alberta Health resource and lets you evaluate it yourself. Review recommended items do not include a suggested change, a revenue estimate, or a confidence indicator. They exist to surface something worth your attention and point you to the authoritative source.

## Suggestion priorities

Each suggestion carries a priority level based on its potential impact:

- **High priority**: estimated revenue impact above $20 or a pattern that historically correlates with rejection rates above 80%. These appear at the top of the suggestions panel.
- **Medium priority**: estimated revenue impact between $5 and $20, or rejection correlation between 50% and 80%.
- **Low priority**: estimated impact below $5 or purely informational items. These appear at the bottom and are easy to scan past.

Review recommended suggestions do not carry a priority level or revenue estimate because the engine is flagging complexity rather than making a quantified recommendation.

## Accepting and dismissing suggestions

When you open a claim with active suggestions, each one appears with an explanation of why it was generated and what you can do about it.

To accept a suggestion, click **Apply**. The claim form updates with the recommended change so you can review it before saving. You still control the final claim; applying a suggestion is the same as editing the field yourself.

To skip a suggestion, click **Dismiss**. The engine asks for a brief reason (for example, "not clinically applicable" or "already considered"). This feedback is optional but helps the engine calibrate future suggestions.

Suggestions you do not act on expire when the claim leaves Draft status. They do not carry forward to submitted or assessed claims.

## How the engine learns from your choices

The advice engine tracks how you respond to suggestions over time and adjusts what it shows you.

Suggestions you frequently accept maintain their priority. If you accept modifier addition suggestions for a particular code nine times out of ten, the engine keeps surfacing them prominently.

Suggestions you frequently dismiss get demoted. After several dismissals of the same suggestion type for similar claim patterns, the engine reduces its priority or stops showing it entirely. If your rejection data later indicates the suppressed suggestion would have prevented a problem, the engine reintroduces it.

New physicians start with suggestion priorities calibrated to their specialty cohort. As you process your first 50 or so claims, the engine shifts from cohort defaults to patterns specific to your coding behaviour. This means the suggestions become more relevant the longer you use the platform.

The engine never changes your claims automatically. Every suggestion requires your explicit action to apply.

For background on the rules engine that runs before the advice engine, see [How the rules engine works](/help-centre/submitting-claims/how-the-rules-engine-works). For an overview of how flags and suggestions appear together on your claims, see [Understanding flags and suggestions on your claims](/help-centre/submitting-claims/understanding-flags-and-suggestions-on-your-claims).
