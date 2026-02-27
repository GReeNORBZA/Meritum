---
title: "Submission preferences explained"
category: submitting-claims
slug: submission-preferences-explained
description: "A detailed explanation of the three submission preference modes, how they interact with the Thursday batch cycle, and when to use each one."
priority: 2
last_reviewed: 2026-02-25
review_cycle: on-change
type: reference
---

# Submission preferences explained

Submission preferences control how your claims move from validated to queued for the weekly Thursday batch. Meritum offers three modes, and you can set them independently for Alberta Health Care Insurance Plan (AHCIP) and Workers' Compensation Board (WCB) claims.

If you just need to set or change your preferences, see [Choosing your submission preferences](/help-centre/getting-started/choosing-your-submission-preferences). This article explains what each mode does, when each one makes sense, and how they interact with the [Thursday submission cycle](/help-centre/submitting-claims/how-the-thursday-submission-cycle-works).

## Clean vs. flagged claims

Before the modes make sense, you need to understand how Meritum classifies claims. A claim is **clean** when it passes all validation checks with zero warnings, has no unresolved flags, and no pending suggestions from the advice engine. A claim is **flagged** when it has any active warning, an unresolved duplicate alert, or an advice engine suggestion you have not yet accepted or dismissed. Errors are different: a claim with validation errors cannot be queued under any mode until the errors are fixed.

## The three modes

### Require Approval

Every claim, clean or flagged, waits for you to explicitly approve it before it enters the submission queue. Nothing submits without your manual review.

This is the right choice if you want to personally verify every claim before it goes to Alberta Health or WCB. Some physicians prefer this when they are new to Meritum, when they work with a small claim volume, or when they want full control over their weekly batch.

**Default for:** WCB claims. WCB submissions involve form-level detail and context-sensitive timing rules where errors carry higher consequences than typical AHCIP code-level rejections.

### Auto-submit clean

Claims that pass all validation checks with no flags are automatically queued for the next Thursday batch. Flagged claims are held until you review them and resolve the flags.

This is the mode most physicians settle into. Routine claims flow straight through without manual approval, while anything that needs your judgment gets held for review. You still receive a reminder before the Thursday cutoff listing any flagged claims waiting for your attention.

**Default for:** AHCIP claims. The weekly AHCIP cycle is predictable, codes are standardized through the Schedule of Medical Benefits (SOMB), and clean claims rarely need a second look.

### Auto-submit all

Both clean and flagged claims are automatically queued. Flagged claims are submitted with their warnings intact. You can still unqueue individual claims before the Thursday noon cutoff if you spot something, but the system will not hold anything back on its own.

Use this mode with caution. Flagged claims may be held or rejected by Alberta Health. This mode makes sense for high-volume physicians who prefer to handle rejections after the fact rather than reviewing flags before submission. If your rejection rate stays low, the time savings can be worth it. If rejections climb, switch back to Auto-submit clean.

## AHCIP and WCB are independent

You set one mode for AHCIP and a separate mode for WCB. Most physicians use Auto-submit clean for AHCIP and Require Approval for WCB; those are the defaults. But you can mix and match however you like. For example, a physician comfortable with WCB forms might use Auto-submit clean for both, while someone who prefers caution might set both to Require Approval.

## How to change your preferences

You choose your submission preferences during onboarding (Step 6 of the setup wizard). After that, go to **Settings > Submission Preferences** to change them at any time.

## Changing preferences mid-week

Changes take effect immediately for claims that have not yet been queued. Here is how that plays out:

- **Claims already queued** for this Thursday's batch stay queued. Changing your mode does not remove them from the queue.
- **Validated but not yet queued claims** are evaluated under your new mode right away. If you switch from Require Approval to Auto-submit clean, any clean validated claims will be queued automatically.
- **Flagged claims held for review** remain held unless you switch to Auto-submit all, in which case they will be queued.

If you are unsure what will end up in this week's batch after a mode change, check the batch preview on the Submissions page. It shows exactly which claims are queued for the upcoming Thursday.

## Which mode should you use?

**Require Approval** is best for new users, low volume, or full control. The trade-off is that every claim needs manual approval.

**Auto-submit clean** is best for most physicians after the first few weeks. Routine claims flow automatically; flagged claims still need review.

**Auto-submit all** is best for high-volume physicians comfortable with post-submission corrections. The trade-off is that flagged claims may be rejected.

There is no penalty for changing modes. Try Auto-submit clean for a few weeks and see how it fits your workflow. You can always adjust.
