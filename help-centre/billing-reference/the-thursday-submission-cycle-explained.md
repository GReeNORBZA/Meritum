---
title: "The Thursday submission cycle explained"
category: billing-reference
slug: the-thursday-submission-cycle-explained
description: "Reference explaining Alberta Health's weekly AHCIP claim processing schedule, from Thursday batch submission through Friday assessment and payment."
priority: 3
last_reviewed: 2026-02-25
review_cycle: quarterly
type: reference
---

Alberta Health processes Alberta Health Care Insurance Plan (AHCIP) claims on a weekly cycle. Physicians and accredited submitters transmit claims every Thursday, Alberta Health assesses them overnight, and results come back on Friday. This article explains why the cycle works this way, what happens at each stage, and how electronic submission fits in.

## Why weekly batches instead of real-time processing

Unlike some insurance systems that process claims individually as they arrive, AHCIP uses batch processing. Alberta Health receives claims from thousands of physicians through hundreds of accredited submitters across the province. Batch processing lets Alberta Health validate all submitted claims against the Schedule of Medical Benefits (SOMB) rules in a single coordinated run, apply cross-claim checks (such as duplicate detection and daily maximums), and return a complete set of results in one response file.

The Thursday submission day is set by Alberta Health. All accredited submitters transmit on the same schedule, which means every physician in the province operates on the same weekly rhythm regardless of which billing platform they use.

## The weekly timeline

The cycle follows a predictable pattern each week:

**Monday through Thursday morning**: physicians create, validate, and queue claims. This is your working window. Claims can be edited, removed from the queue, or added freely during this period.

**Thursday at 12:00 noon Mountain Time**: the weekly cutoff. At this point, all queued AHCIP claims are locked into the current week's batch. Any claims queued after this cutoff carry over to the following Thursday. There is no mid-week or off-cycle submission option for AHCIP.

**Thursday 12:00 to 14:00 MT**: batch assembly. Your billing platform groups queued claims by Business Arrangement (BA) number, runs a final round of validation, and generates the submission files. Each BA number produces its own file, because Alberta Health processes claims per BA. If you hold multiple BA numbers (common for Physician Comprehensive Care Model physicians with both capitated and fee-for-service arrangements), each one generates a separate batch.

**Thursday afternoon**: transmission. The assembled files are transmitted to Alberta Health through H-Link, the province's secure electronic claims submission channel. Once transmission completes, your claims move from a queued state to a submitted state. For more on how H-Link works, see [H-Link: what it is and how electronic claims submission works](/help-centre/billing-reference/h-link-what-it-is-and-how-electronic-claims-submission-works).

**Friday**: assessment results. Alberta Health processes the submitted claims overnight and returns an assessment file, typically available on Friday. Each claim receives one of three outcomes: paid, held for review, or refused. Paid claims follow Alberta Health's standard remittance schedule for deposit. Held and refused claims include explanatory codes describing why Alberta Health did not pay the claim as submitted.

**Friday onward**: payment. For accepted claims, Alberta Health deposits payment according to its remittance schedule. The deposit covers all paid claims from that week's batch.

## What happens behind the scenes during batch assembly

When the Thursday cutoff arrives, the submission process is fully automated. Here is what your billing platform does on your behalf:

First, it collects all claims in the queue and groups them by BA number. Claims are ordered by date of service within each group.

Next, it runs a final pre-submission validation pass. This catches any issues that may have emerged since the claim was first validated; for example, a SOMB update that took effect between when you created the claim and when the batch closes. Claims that fail this final check are pulled from the batch and returned so you can review them. The rest of the batch proceeds.

Then the platform generates a structured submission file for each BA. The file contains a header (identifying the submitter and batch), individual claim records (one per service, formatted per the Electronic Claims Submission Specifications Manual), and a trailer (containing a record count and total value for integrity verification).

Finally, the file is transmitted to Alberta Health via H-Link over a secure connection. The platform logs the transmission result and notifies you of the outcome: how many claims were submitted and the total submitted value.

## How electronic submission works

Physicians do not submit claims to Alberta Health directly. Submission happens through accredited submitters: organizations that have completed Alberta Health's accreditation process and are authorized to transmit claims via H-Link. Your billing platform acts as your accredited submitter.

H-Link is the secure transmission channel that connects accredited submitters to Alberta Health's claims processing system. It handles both the outbound submission of claim files and the inbound retrieval of assessment results. The connection uses secure protocols, and all transmitted data is treated as protected health information under the Health Information Act (HIA).

When Alberta Health receives your batch, it validates each claim against the SOMB rules that were in effect on the date of service. This includes checking that the Health Service Code (HSC) is valid, that governing rules are satisfied (referral requirements, visit limits, time-based billing rules), that modifier combinations are permitted, and that no duplicate claims exist. Claims that pass assessment are approved for payment. Claims that fail receive one or more explanatory codes describing the issue.

## Assessment results and what they mean

The assessment file your platform retrieves on Friday contains a record for each submitted claim. Each record includes the original claim reference, the payment status, the amount Alberta Health will pay (which may differ from the submitted amount if a fee was adjusted), and any explanatory codes.

Explanatory codes fall into a few broad categories: claim data errors (missing or invalid fields), governing rule violations (such as exceeding visit limits or missing a required referral), payment adjustments (fee reductions, modifier disallowances, duplicate prevention), and administrative issues (patient eligibility or provider status problems). Your billing platform translates these codes into readable descriptions so you can decide whether to correct and resubmit.

## Relationship to Meritum's submission workflow

This article describes the AHCIP weekly cycle as it applies to all Alberta physicians regardless of platform. For the specific steps you follow in Meritum to prepare and submit your Thursday batch, see [How the Thursday submission cycle works](/help-centre/submitting-claims/how-the-thursday-submission-cycle-works).
