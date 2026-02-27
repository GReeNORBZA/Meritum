---
title: "Understanding flags and suggestions on your claims"
category: submitting-claims
slug: understanding-flags-and-suggestions-on-your-claims
description: "Learn how to read and act on rules engine flags and advice engine suggestions that appear on your claims."
priority: 1
last_reviewed: 2026-02-25
review_cycle: on-change
type: procedural
---

When you save or edit a claim, Meritum runs two separate systems against it: the rules engine and the advice engine. The rules engine catches problems that could get your claim refused. The advice engine spots billing opportunities you may have missed. Both display their results on the claim detail page, but they serve different purposes and call for different responses.

## Rules engine flags

The rules engine checks every claim against Alberta Health Care Insurance Plan (AHCIP) structural requirements, Schedule of Medical Benefits (SOMB) governing rules, and your submission history. It runs automatically when you save a claim and again when the claim enters the submission queue.

Flags come in two severity levels:

- **Errors** block submission. You must fix these before the claim can move forward. Common examples: a missing diagnostic code when the health service code's governing rules require one, a modifier that is not eligible for the selected code, or a date of service outside the valid submission window.

- **Warnings** do not block submission but flag something worth reviewing. Common examples: a health service code that is unusual for the patient's age group, or approaching the 90-day AHCIP submission deadline. You can submit a claim with active warnings; they exist so you can make an informed decision rather than discover the issue after assessment.

## Advice engine suggestions

The advice engine analyses your claim after validation and generates billing optimisation recommendations. Suggestions are always optional. They highlight opportunities; they never prevent you from submitting.

Suggestions fall into categories such as:

- **Modifier recommendations**: an eligible modifier you have not applied, or a modifier that may not be appropriate for this encounter.
- **Code alternatives**: a different health service code that better matches the documented service, sometimes with a higher reimbursement.
- **Missed billing**: a service pattern the advice engine recognises from your recent encounters that you may have forgotten to bill separately.
- **Rejection risk**: something about the claim that historically correlates with AHCIP refusals, even though it passes structural validation.

Each suggestion includes a brief explanation of why it was generated and what action you can take. Suggestions are prioritised: high-priority items typically involve amounts over $20 or significant rejection risk; lower-priority items are informational.

## How to resolve flags

1. Open the flagged claim from your **Claims** list. Flags appear in a panel at the top of the claim detail page.
2. Read each flag. Errors are marked in red; warnings in yellow.
3. For errors, edit the relevant field on the claim to correct the issue. The flag clears automatically once the value passes validation.
4. For warnings, review the flag description and decide whether to adjust the claim or proceed as-is.
5. Once all errors are resolved, the claim moves from Flagged to Clean status.

## How to act on suggestions

1. Open the claim and scroll to the **Suggestions** section below the flags panel.
2. Review each suggestion. The explanation tells you what the advice engine found and why it matters.
3. To accept a suggestion, click **Apply**. The claim form updates with the recommended change for your review.
4. To skip a suggestion, click **Dismiss**. The advice engine learns from your decisions over time; if you consistently dismiss a particular type of suggestion, it will stop showing it.

Flags prevent rejected claims. Suggestions help recover revenue. Both are worth your attention, but only errors require action before you can submit.

For deeper detail on each system, see [How the rules engine works](/help-centre/submitting-claims/how-the-rules-engine-works) and [How the advice engine works](/help-centre/submitting-claims/how-the-advice-engine-works).
