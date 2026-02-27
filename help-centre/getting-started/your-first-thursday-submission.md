---
title: "Your first Thursday submission: what to expect"
category: getting-started
slug: your-first-thursday-submission
description: "Step-by-step walkthrough of what happens during your first Thursday AHCIP batch submission and when to expect results."
priority: 1
last_reviewed: 2026-02-25
review_cycle: on-change
type: procedural
---

Alberta Health Care Insurance Plan (AHCIP) claims are submitted in weekly batches every Thursday. Your first batch will likely be small, and that is completely normal. Here is what to do before, during, and after your first submission.

## Before Thursday: get your claims ready

Meritum can only include claims that have passed validation and are queued for submission. Before the Thursday cutoff:

1. Open the **Claims** page and check for any claims in **Draft** or **Flagged** status. Draft claims have not been validated yet; flagged claims need you to resolve warnings or advice engine suggestions before they can move forward.
2. Review each flagged claim and either accept the flags or correct the underlying issue. Once resolved, the claim moves to **Validated** status.
3. Depending on your submission preferences, validated claims either queue automatically or wait for your approval. If you chose **Require Approval** mode, go to the **Ready for Review** list and approve the claims you want included in this week's batch. If you chose **Auto-submit clean**, clean claims queue themselves; you only need to handle flagged ones.
4. Confirm that your queued claims appear under **Queued for Submission** on the Claims page. Any claim showing there by Thursday at noon will be included.

If you are unsure which submission mode you selected, check **Settings > Submission Preferences**. You can change modes at any time; the new setting takes effect for the next batch.

## Thursday: the cutoff and batch assembly

The weekly cutoff is **Thursday at 12:00 noon Mountain Time**. After that point, no new claims enter the current batch.

Between 12:00 and 14:00 MT, Meritum assembles your batch automatically. Here is what happens behind the scenes:

1. The system groups your queued claims by Business Arrangement (BA) number. Each BA produces its own H-Link file, because Alberta Health processes claims per BA.
2. Meritum generates the H-Link files: a header record, individual claim records, and a trailer record summarising the batch.
3. The files are transmitted to Alberta Health over an encrypted connection. You do not need to do anything during this step.

Once transmission completes, your claims move from **Queued** to **Submitted** status. You will see this status change on the Claims page.

## Friday: assessment results

Alberta Health typically returns assessment results on Friday. Meritum retrieves the assessment file automatically, matches each result back to your submitted claims, and updates their status:

- **Accepted**: the claim was assessed and approved for payment. Payment follows Alberta Health's standard schedule.
- **Held**: Alberta Health needs additional information or the claim is under review. The hold reason code appears on the claim detail page.
- **Refused**: the claim was rejected. The refusal reason code and a plain-language explanation appear on the claim detail page so you can decide whether to correct and resubmit.

For a full breakdown of what each assessment status and reason code means, see [Understanding your assessment results](/help-centre/after-submission/understanding-your-assessment-results).

## Your first batch may be small

If you onboarded mid-week or only entered a handful of claims, your first Thursday batch might contain just a few items. That is expected. The weekly rhythm builds naturally as you add claims throughout the week. For a detailed look at how the Thursday cycle repeats and how to plan around it, see [How the Thursday submission cycle works](/help-centre/submitting-claims/how-the-thursday-submission-cycle-works).
