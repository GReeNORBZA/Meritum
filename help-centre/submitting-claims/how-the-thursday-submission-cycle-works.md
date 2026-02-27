---
title: "How the Thursday submission cycle works"
category: submitting-claims
slug: how-the-thursday-submission-cycle-works
description: "Week-by-week breakdown of the Thursday AHCIP batch submission cycle, from claim preparation through Friday assessment results."
priority: 1
last_reviewed: 2026-02-25
review_cycle: on-change
type: procedural
---

Every Alberta Health Care Insurance Plan (AHCIP) claim in Meritum follows a weekly rhythm: you create and validate claims throughout the week, and the platform submits them in a single batch every Thursday. Here is how each stage works.

## 1. Throughout the week: create, validate, and queue

As you see patients, create claims and let the validation engine check them. Resolve any flags, then move validated claims into the queue. Depending on your submission preferences, clean claims may queue automatically or wait for your manual approval.

Any claim showing **Queued for Submission** status on the Claims page will be picked up at the Thursday cutoff. You can add, edit, or remove queued claims freely until that point.

## 2. Thursday 12:00 noon MT: the cutoff

The weekly cutoff is **Thursday at 12:00 noon Mountain Time**. Claims queued by this time are locked into the current week's batch. Claims queued after 12:00 MT Thursday roll to the following week's batch; there is no way to add them to a batch that has already closed.

The Claims page displays a countdown to the next Thursday cutoff so you always know how much time you have.

## 3. Thursday 12:00 to 14:00 MT: batch assembly

Between noon and 14:00, Meritum assembles your batch automatically. The system:

1. Groups your queued claims by Business Arrangement (BA) number. Each BA produces its own H-Link file, because Alberta Health processes claims per BA.
2. Runs a final round of pre-submission validation. If a claim fails this check, it returns to **Validated** status and stays behind for you to review. The rest of the batch proceeds without it.
3. Generates the H-Link files: a header record identifying the batch, individual claim records ordered by date of service, and a trailer record summarising the totals.

If you are a Physician Comprehensive Care Model (PCPCM) physician with a dual-BA setup, you will see two separate batches each Thursday: one for in-basket claims submitted under your PCPCM BA, and one for out-of-basket claims submitted under your fee-for-service BA.

## 4. Thursday afternoon: transmission to Alberta Health

After assembly, the H-Link files are transmitted to Alberta Health over a secure connection. Your claims move from **Queued** to **Submitted** status, and you receive a confirmation notification. You do not need to do anything during this step.

If a transmission fails, Meritum retries automatically. If the issue persists after multiple retries, the batch is marked with an error and you are notified so support can help resolve it.

## 5. Friday: assessment results

Alberta Health typically returns assessment results on Friday. Meritum retrieves the results, matches them to your submitted claims, and updates each claim's status:

- **Paid**: the claim was accepted and payment follows Alberta Health's standard schedule.
- **Held**: Alberta Health needs more information or is reviewing the claim. The hold reason code appears on the claim detail page.
- **Refused**: the claim was rejected. The refusal code and a plain-language explanation appear on the claim detail page so you can decide whether to correct and resubmit.

The cycle then resets. Claims you create the following week queue toward the next Thursday cutoff.

For a conceptual overview of why AHCIP uses weekly batches, see [The Thursday submission cycle explained](/help-centre/billing-reference/the-thursday-submission-cycle-explained). If this is your first time going through the cycle, see [Your first Thursday submission](/help-centre/getting-started/your-first-thursday-submission).
