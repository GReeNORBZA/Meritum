---
title: "Understanding the Schedule of Medical Benefits"
category: billing-reference
slug: understanding-the-schedule-of-medical-benefits
description: "How Alberta's Schedule of Medical Benefits is structured and how physicians use it to identify billable services and fees."
priority: 3
last_reviewed: 2026-02-25
review_cycle: quarterly
type: reference
---

The Schedule of Medical Benefits (SOMB) is the fee schedule published by Alberta Health that lists every insured health service and its corresponding fee. If a service is in the SOMB, you can bill it through the Alberta Health Care Insurance Plan (AHCIP). If it is not, the service is either uninsured or billed through a different pathway. Every claim you create in Meritum references the SOMB to determine the correct fee for the service you performed.

## How the SOMB is structured

The SOMB organizes services by section, with each section roughly corresponding to a medical specialty or service category. Within each section, individual services are identified by a Health Service Code (HSC): a short alphanumeric code that represents a specific procedure, visit type, consultation, or diagnostic service.

Each HSC entry in the SOMB includes several pieces of information:

- **Description**: what the service is, in Alberta Health's terminology.
- **Base fee**: the amount Alberta Health pays for a single instance of the service.
- **Fee type**: whether the fee is a flat rate, time-based, or percentage-based.
- **Specialty and facility restrictions**: which physician specialties or facility types are permitted to bill the code.
- **Modifier eligibility**: which modifiers can be applied to adjust the fee.
- **Billing limits**: maximum units per day, per patient, or per encounter where applicable.
- **Referral requirements**: whether a referring practitioner number is required.

There are over 6,000 HSC entries in the current SOMB. You do not need to memorize them. When creating a claim in Meritum, you search for the code by keyword or HSC number, and the platform fills in the fee and validation rules automatically.

## Governing rules

The SOMB is more than a list of codes and fees. It also contains governing rules: constraints that define when and how specific codes can be billed. These rules appear in the SOMB preamble and in the governing rules section (abbreviated as "GR" followed by a number).

Key governing rules include:

- **GR 1 (General)**: baseline rules that apply to all claims, including requirements around documentation and service eligibility.
- **GR 3 (Visit Limits)**: caps on how many times certain codes can be billed for the same patient within a defined period.
- **GR 5 (Diagnostic Imaging)**: rules specific to diagnostic imaging interpretations and technical fees.
- **GR 8 (Referrals)**: requirements for specialist consultations to include a referring practitioner number.
- **GR 10 (Surgical)**: billing rules for surgical procedures, including pre- and post-operative care bundling.
- **GR 14 (Obstetric)**: rules for obstetric service billing, including global maternity fees.
- **GR 18 (Chronic Disease Management)**: rules for chronic care management codes and care plan services.

When you save a claim in Meritum, the rules engine checks it against applicable governing rules and flags conflicts before submission. For more on how this works, see [How the rules engine works](/help-centre/submitting-claims/how-the-rules-engine-works).

## Modifiers

A modifier is a code you attach to a claim that adjusts the base fee. Modifiers account for circumstances that change the value of a service without changing the service itself.

Modifiers come in three types:

- **Explicit modifiers** require you to add them manually. You choose to apply the modifier because the clinical circumstances call for it.
- **Implicit modifiers** are applied automatically by the system based on claim data. For example, a time-based premium may be calculated from the time spent field without you needing to attach a modifier code.
- **Semi-implicit modifiers** are suggested by the platform based on claim context, but require your confirmation before they are applied.

Common modifiers include the Comprehensive General Practitioner Modifier (CMGP) for qualifying office visits, the After-Hours (AFHR) premium for services outside standard hours, the Locum Supply for Continuous Days (LSCD) modifier, the Rural and Remote Northern Program (RRNP) premium, the Telehealth Modifier (TM) for virtual encounters, and the Anaesthesia (ANE) modifier for anaesthesia services. Each modifier has its own calculation method: some apply a percentage to the base fee, some add a fixed amount, and some use a multiplier.

You can attach up to three modifiers per claim. Meritum validates that each modifier is eligible for the HSC you selected and flags conflicts if two modifiers cannot be used together. For detail on after-hours premiums specifically, see [After-hours billing and time premiums](/help-centre/billing-reference/after-hours-billing-and-time-premiums).

## Quarterly updates and bulletins

Alberta Health updates the SOMB on a quarterly cycle: January, April, July, and October. Updates may add new codes, retire old ones, change fee amounts, or revise governing rules. Between quarterly releases, Alberta Health occasionally publishes mid-quarter bulletins that announce immediate changes.

Meritum tracks every SOMB release and bulletin. When you create or validate a claim, the platform uses the fee schedule that was in effect on the date of service, not the date you happen to be entering the claim. This means you do not need to check which version of the SOMB applies; the platform handles version matching automatically.

## Looking up codes in Meritum

Rather than consulting the SOMB PDF directly, you search for codes within Meritum. The code search supports lookup by HSC number, keyword, or description fragment. Results show the base fee, modifier eligibility, and any governing rule restrictions for each code. If a code has specific billing limits or referral requirements, those appear alongside the search result so you can verify eligibility before adding it to a claim.

If Alberta Health has recently updated a code or added a new one, it appears in search results as soon as Meritum processes the quarterly update or mid-quarter bulletin. For a broader overview of how claims move through the system, see [AHCIP fee-for-service billing: how the system works](/help-centre/billing-reference/ahcip-fee-for-service-billing-how-the-system-works). For explanatory codes you may encounter after submission, see [Common AHCIP explanatory codes](/help-centre/billing-reference/common-ahcip-explanatory-codes-and-what-they-mean).
