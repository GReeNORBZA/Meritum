---
title: "Reading rejection codes"
category: after-submission
slug: reading-rejection-codes
description: "How to interpret AHCIP explanatory codes on refused or adjusted claims and understand what corrective action to take."
priority: 2
last_reviewed: 2026-02-25
review_cycle: on-change
type: reference
---

When Alberta Health refuses or adjusts a claim, the assessment result includes one or more explanatory codes that tell you why. Meritum translates each code into a plain-language explanation and suggests what to do next.

## What explanatory codes are

Explanatory codes are short alphanumeric codes returned by Alberta Health Care Insurance Plan (AHCIP) in assessment responses. Every claim that is refused, held, or paid at a different amount than you submitted will have at least one explanatory code attached. The code identifies the specific reason the claim was not paid as submitted.

A single claim can have multiple explanatory codes. For example, a claim might be refused because the health service code (HSC) required a referral and the date of service fell outside the submission window. That claim would show two codes: one for the missing referral and one for the expired date.

## Where to find explanatory codes in Meritum

Open any claim with a Refused or Adjusted status from the **Claims** page. The claim detail view shows each explanatory code along with:

- The official AHCIP code and description
- A plain-language explanation of what typically causes this code
- Corrective guidance describing how to fix the issue
- For common rejections, a one-click action button that takes you directly to the relevant field or form

You do not need to look up codes manually. Meritum resolves every code against its reference data and presents the explanation inline.

## Explanatory code categories

Explanatory codes fall into four broad categories. Knowing which category a code belongs to helps you decide how to respond.

### Claim errors

These codes mean the claim had missing or invalid data that prevented AHCIP from processing it. Common examples:

- **Invalid or retired HSC code**: the health service code was not active on the date of service. This happens when the Schedule of Medical Benefits (SOMB) retires a code between the encounter and submission.
- **Missing diagnostic code**: the HSC's governing rules require a diagnostic code, but none was provided.
- **Invalid facility number**: the encounter was hospital-based but the facility number was missing or unrecognized.
- **Expired submission window**: the date of service is more than 90 days in the past.

Claim errors are usually straightforward to fix. Correct the invalid field and resubmit.

### Governing rule violations

These codes indicate the claim broke one of the AHCIP governing rules associated with the HSC code. Governing rules control when and how a service can be billed. Common examples:

- **Visit limit exceeded (Governing Rule 3)**: the patient has already reached the maximum number of visits allowed for this service in the billing period.
- **Referral required (Governing Rule 8)**: the HSC code is a specialist consultation that requires a referring practitioner, but no referral was included on the claim.
- **Bundling applied**: two services billed on the same date for the same patient are considered bundled under the governing rules, and only the higher-value code is payable.
- **Modifier not permitted**: a modifier was applied that does not qualify under the governing rules for that HSC code.

Review the specific rule to determine whether the claim can be corrected or whether the service is genuinely not payable in this context.

### Payment adjustments

These codes appear on claims that AHCIP accepted but paid at a different amount than submitted. The claim shows as Paid with an adjustment note rather than Refused. Common examples:

- **Fee reduced per schedule**: the submitted fee exceeded the SOMB rate for the code. AHCIP paid the schedule amount instead.
- **Modifier disallowed**: a premium modifier was removed because the conditions for it were not met.
- **Duplicate payment prevention**: AHCIP identified the claim as a potential duplicate of a previously paid claim and reduced the payment accordingly.

For adjusted claims, review the difference between your submitted amount and the assessed amount on the claim detail page. The explanatory code tells you which rule caused the adjustment.

### Administrative issues

These codes relate to the patient's coverage status or your provider registration rather than the claim itself. Common examples:

- **Patient not eligible on date of service**: the patient's AHCIP coverage was not active on the encounter date. This can happen when coverage has lapsed or the patient recently moved to Alberta.
- **Provider not registered for service**: your registration does not include the program or service type for the HSC code.
- **Business Arrangement issue**: the Business Arrangement (BA) number does not match an active arrangement for your practice.

Administrative issues often require action outside of Meritum, such as confirming coverage status with Alberta Health or verifying your BA registration.

## How Meritum helps you respond

Meritum's validation engine runs 19 pre-submission checks that correspond to the most common explanatory codes. Missing referrals, invalid HSC codes, expired dates, and modifier conflicts are caught before your claim leaves the platform. If you see a rejection code that one of these checks would have caught, it typically means the claim bypassed validation.

For each code on a refused claim, Meritum shows corrective guidance in plain language. Where possible, the platform offers a one-click corrective action: add a referral directly from the rejection view, or search for a replacement HSC code without leaving the claim.

For a detailed list of frequently seen codes and their resolutions, see [Common AHCIP explanatory codes and what they mean](/help-centre/billing-reference/common-ahcip-explanatory-codes-and-what-they-mean). For step-by-step instructions on fixing and resubmitting a refused claim, see [Correcting and resubmitting refused claims](/help-centre/after-submission/correcting-and-resubmitting-refused-claims).

## The official explanatory code reference

Alberta Health publishes the complete list of explanatory codes as part of the AHCIP claim submission specifications. Meritum does not reproduce the full list, but every code you encounter on your claims is resolved and explained within the platform. If you need to look up a code that does not appear on one of your claims, the official reference is available through the Alberta Health practitioner portal.
