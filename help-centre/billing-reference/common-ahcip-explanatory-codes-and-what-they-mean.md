---
title: "Common AHCIP explanatory codes and what they mean"
category: billing-reference
slug: common-ahcip-explanatory-codes-and-what-they-mean
description: "Plain-language explanations of frequently encountered AHCIP explanatory codes, organized by category, with corrective actions for each."
priority: 3
last_reviewed: 2026-02-25
review_cycle: quarterly
type: reference
---

When Alberta Health Care Insurance Plan (AHCIP) refuses or adjusts a claim, the assessment response includes one or more explanatory codes identifying why. This article covers the codes physicians encounter most often and what to do about each one. For background on where to find these codes on your claims, see [Reading rejection codes](/help-centre/after-submission/reading-rejection-codes).

## Claim errors

Claim errors mean the submission had missing or invalid data. These are usually the simplest to resolve: correct the field and resubmit.

**Missing diagnostic code.** The health service code (HSC) requires a diagnostic code under its governing rules, but none was provided. Open the claim, add a valid ICD diagnostic code, and resubmit. The rules engine catches this before submission, so this code typically appears only on claims that bypassed validation.

**Invalid or expired HSC code.** The HSC was not active on the date of service. This happens when the Schedule of Medical Benefits (SOMB) retires or replaces a code between the encounter and submission. Look up the replacement code in the code search and resubmit.

**Invalid Personal Health Number (PHN) format.** The patient's PHN failed Alberta Health's validation. Verify the PHN on file matches the patient's Alberta Health card. Common causes: transposed digits, an out-of-province number entered in the PHN field, or a coverage number that has been replaced.

**Expired submission window.** AHCIP requires claims to be submitted within 90 calendar days of the date of service. If this window has passed, the claim cannot be resubmitted through normal channels. You will need to contact Alberta Health directly about a late submission request.

## Governing rule violations

These codes indicate the claim conflicted with one of the SOMB governing rules for the HSC code. The service may not be billable as submitted, or an additional field may be required.

**Visit limit exceeded (Governing Rule 3).** The patient has reached the maximum billable visits for this code in the current period. Review your billing history for the patient and code combination. If the limit has genuinely been reached, the service is not payable under that code. A different HSC may apply if the visit was clinically distinct.

**Referral required (Governing Rule 8).** Specialist consultation codes require a referring practitioner billing number. Open the claim, add the referring physician's practitioner number, and resubmit. Meritum offers a one-click action: from the rejection detail view, select **Add referral** to go directly to the referral field.

**Modifier not eligible for this code.** A modifier was applied that the SOMB does not permit for the selected HSC. Remove the modifier or verify the HSC is correct. For example, the Comprehensive General Practitioner Modifier (CMGP) is only valid on a defined set of office visit codes; applying it to a code outside that set triggers this rejection.

**Bundling applied.** Two services billed on the same date for the same patient are considered bundled under the governing rules, and only the higher-value code is payable. Review the pair of codes to confirm they are genuinely bundled. If the services were clinically independent and performed in separate encounters, check whether modifier or location data can distinguish them.

## Payment adjustments

These codes appear on claims that AHCIP accepted but paid at a different amount than submitted. The claim status shows **Paid** with an adjustment note rather than **Refused**.

**Fee reduced per schedule.** The submitted amount exceeded the SOMB rate for the code, and Alberta Health paid the schedule amount instead. This often occurs when the SOMB rate changed in a quarterly update and the claim used the previous fee. In Meritum, fees are looked up automatically by date of service, so this code is uncommon unless the fee was overridden manually.

**Modifier disallowed.** A premium modifier was submitted, but Alberta Health determined the conditions were not met and paid the base fee without the modifier. Review the modifier's eligibility criteria in the SOMB.

**Duplicate payment prevention.** AHCIP identified a potential duplicate of a previously paid claim and reduced or zeroed the payment. Check your claim history for the same patient, code, and date of service. If the claim is genuinely distinct, contact Alberta Health with supporting documentation.

## Administrative issues

These codes relate to patient coverage or provider registration rather than the claim data itself. They often require action outside of Meritum.

**Patient not eligible on date of service.** The patient's AHCIP coverage was not active on the encounter date. This can happen when coverage has lapsed, the patient recently moved to or from Alberta, or the patient is covered under a different plan such as federal coverage. Confirm coverage status with Alberta Health before resubmitting.

**Provider not registered for this service.** Your registration does not include the program or service type required for the HSC code. Verify your registration with Alberta Health; some codes require specific program enrollment beyond your base practitioner registration.

**Business Arrangement not active.** The Business Arrangement (BA) number on the claim does not match an active arrangement. Confirm your BA status in your Meritum account under **Provider settings**. If the BA was recently created, there may be a delay before Alberta Health recognizes it.

## How Meritum reduces these rejections

The rules engine runs 19 pre-submission checks that map to the most common explanatory codes above. Missing referrals, visit limit breaches, modifier conflicts, diagnostic code requirements, and the 90-day window are all caught before your claim reaches AHCIP. For detail on how these checks work, see [How the rules engine works](/help-centre/submitting-claims/how-the-rules-engine-works).

When a code does come back on an assessed claim, Meritum resolves it to a plain-language explanation and corrective guidance. Where a one-click fix is available, the action appears directly on the claim detail screen.

Meritum does not reproduce the full Alberta Health explanatory code list. Every code on your claims is resolved and explained within the platform. For the complete official reference, consult the AHCIP claim submission specifications through the Alberta Health practitioner portal.
