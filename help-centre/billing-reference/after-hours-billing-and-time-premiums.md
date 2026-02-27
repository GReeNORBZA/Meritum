---
title: "After-hours billing and time premiums"
category: billing-reference
slug: after-hours-billing-and-time-premiums
description: "How after-hours premiums and time-based modifiers work in AHCIP, including time-period definitions, statutory holidays, and CMGP documentation requirements."
priority: 3
last_reviewed: 2026-02-25
review_cycle: quarterly
type: reference
---

Alberta Health Care Insurance Plan (AHCIP) claims are eligible for after-hours premiums when you provide services outside standard weekday hours. The premium is a percentage added to the base fee of the Health Service Code (HSC) on the claim, calculated separately from other modifiers. Meritum detects after-hours eligibility automatically based on the time and date of service; you do not need to look up which modifier applies.

## Time periods and modifiers

AHCIP defines three after-hours time periods, each with its own modifier:

- **AFHR (After-Hours Regular Evening)**: weekdays from 17:00 to 23:00. This covers services provided after a typical office day ends but before the overnight period begins.
- **NGHR (Night Hours)**: weekdays from 23:00 to 08:00 the following morning. This applies to overnight services, including emergency department visits and hospital calls during the night.
- **WKND (Weekend and Statutory Holiday)**: all hours on Saturdays, Sundays, and the Alberta statutory holidays listed below. Any service on a qualifying day receives the weekend/holiday premium regardless of the time it was provided.

These modifiers are mutually exclusive on a single claim. A service provided at 02:00 on a Tuesday uses NGHR; the same service at 02:00 on a Saturday uses WKND. The statutory holiday modifier takes precedence when a holiday falls on a weekday.

## Alberta statutory holidays

Ten Alberta statutory holidays qualify for the WKND after-hours premium:

1. New Year's Day (January 1)
2. Family Day (third Monday in February)
3. Good Friday (date varies)
4. Victoria Day (Monday before May 25)
5. Canada Day (July 1)
6. Heritage Day (first Monday in August)
7. Labour Day (first Monday in September)
8. National Day for Truth and Reconciliation (September 30)
9. Thanksgiving (second Monday in October)
10. Remembrance Day (November 11)
11. Christmas Day (December 25)

When a statutory holiday falls on a weekend, the observed day (typically the following Monday) also qualifies. Meritum maintains a statutory holiday calendar in its reference data and checks each claim's date of service against it automatically.

## How the premium is calculated

The after-hours premium is a percentage of the base fee for the HSC on the claim. The percentage varies by time period and is set by Alberta Health in the Schedule of Medical Benefits (SOMB). The calculation is straightforward: the platform multiplies the base fee by the applicable percentage and adds the result to the claim total as a separate line item.

For example, if you bill a service with a base fee of $100.00 and the after-hours premium rate for that time period is 15%, the premium adds $15.00 to the claim. The submitted amount becomes $115.00 before any other modifiers or premiums. The fee breakdown on the claim detail page shows the after-hours premium as its own line so you can verify it.

After-hours premiums are calculated independently from other premiums such as the Rural and Remote Northern Program (RRNP) or the Comprehensive Medical General Practitioner (CMGP) modifier. Each premium is computed against the base fee separately, then summed. They do not compound.

Not every HSC is eligible for after-hours premiums. The SOMB defines which codes qualify. If a code is ineligible, the modifier will not appear in the fee breakdown even if the time of service falls within an after-hours period. Meritum checks modifier eligibility as part of claim validation and will not apply an ineligible premium.

## Time-based modifiers and CMGP

The CMGP modifier applies to qualifying office visits where the encounter exceeds a minimum duration. Unlike after-hours modifiers, CMGP is semi-implicit: Meritum suggests it when the time spent on the encounter meets the threshold, but you must confirm before it is applied.

To use CMGP, you need to document the start time, end time, and total duration of the encounter. The time spent must exceed 15 minutes to qualify. CMGP uses time-based units, typically calculated in 15-minute increments after the initial qualifying period. The premium is added to the base fee as a separate line item, independent of any after-hours or RRNP premiums on the same claim.

CMGP is not applicable to virtual care codes. The rules engine validates CMGP eligibility against the HSC and flags conflicts if you attempt to apply it to an ineligible code. Related time-based modifiers include LSCD (Locum Supply for Continuous Days), which functions as a prolonged add-on and requires CMGP to be present on the claim.

## After-hours detection in Meritum

When you create a claim, the platform checks the date and time of service against the after-hours time periods and statutory holiday calendar. If the service qualifies, the applicable modifier is applied automatically and the premium appears in the fee breakdown.

During emergency department shifts logged through the mobile companion, after-hours eligibility is detected from the shift start and end times. A subtle indicator on each logged encounter shows whether it qualifies for an after-hours premium. You confirm the modifier during your desktop review before submission; the mobile companion does not apply premiums without your review.

For a broader look at how fees and modifiers interact, see [Understanding the Schedule of Medical Benefits](/help-centre/billing-reference/understanding-the-schedule-of-medical-benefits).
