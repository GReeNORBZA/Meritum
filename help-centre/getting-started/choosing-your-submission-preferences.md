---
title: "Choosing your submission preferences"
category: getting-started
slug: choosing-your-submission-preferences
description: "Set how Meritum handles claim submission for AHCIP and WCB: require manual approval, auto-submit clean claims, or auto-submit everything."
priority: 1
last_reviewed: 2026-02-25
review_cycle: on-change
type: procedural
---

Submission preferences control whether Meritum queues your claims for the next batch automatically or waits for you to approve each one. You set them during Step 6 of the onboarding wizard, but this step is optional; if you skip it, sensible defaults apply and you can change them any time from your account settings.

## The three submission modes

Meritum classifies every claim as either **clean** or **flagged** before it enters a batch. A clean claim has passed all validation rules with no warnings, no unresolved advice engine suggestions, and no duplicate alerts. A flagged claim has at least one item that needs your attention.

Your submission mode determines what happens to each type:

1. **Require Approval**: Every claim, whether clean or flagged, waits for your explicit approval before it enters a batch. Nothing is submitted without you reviewing it first.
2. **Auto-submit clean**: Clean claims are automatically queued for the next batch. Flagged claims are held back until you review and resolve the flags. This is the default for Alberta Health Care Insurance Plan (AHCIP) claims.
3. **Auto-submit all**: Both clean and flagged claims are automatically queued. This mode trusts the system entirely and submits everything unless you intervene. Use it with caution; flagged claims may contain issues that affect reimbursement.

## Setting your preferences during onboarding

1. On Step 6 of the onboarding wizard, you see two independent dropdowns: one for AHCIP and one for Workers' Compensation Board (WCB).
2. Select your preferred mode for **AHCIP claims**. The default is Auto-submit clean.
3. Select your preferred mode for **WCB claims**. The default is Require Approval, because WCB timing rules and form requirements are more sensitive to errors.
4. Click **Continue** to save your choices.

If you skip this step, Meritum applies the defaults described above. You can revisit your submission preferences at any time under **Settings > Submission Preferences**.

## Why AHCIP and WCB default differently

AHCIP claims follow a predictable weekly batch cycle and use standardised fee codes from the Schedule of Medical Benefits (SOMB). Clean AHCIP claims rarely need manual review before submission, so auto-submitting them saves time without adding risk.

WCB claims involve form-level detail that varies by contract type and injury context. Errors on WCB forms can delay payment or trigger follow-up requests from the adjudicator. Starting with Require Approval gives you a chance to review each WCB claim before it ships, and you can switch to a more automated mode once you are comfortable with the workflow.

## Changing your preferences later

Go to **Settings > Submission Preferences** to update your modes at any time. Changes take effect immediately for the next batch cycle. Claims already queued in the current batch are not affected.

For a deeper look at how each mode interacts with the batch assembly process and the advice engine, see [Submission preferences explained](/help-centre/submitting-claims/submission-preferences-explained).
