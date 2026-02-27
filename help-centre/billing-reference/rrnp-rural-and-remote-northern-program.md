---
title: "RRNP: Rural and Remote Northern Program"
category: billing-reference
slug: rrnp-rural-and-remote-northern-program
description: "How the RRNP premium works, which communities qualify, and how Meritum calculates it automatically based on your practice location."
priority: 3
last_reviewed: 2026-02-25
review_cycle: quarterly
type: reference
---

The Rural and Remote Northern Program (RRNP) is a premium that Alberta Health adds to Alberta Health Care Insurance Plan (AHCIP) fee-for-service claims for physicians practising in eligible communities. If your practice location is in a qualifying community, every claim you bill from that location receives a percentage increase on top of the base fee. Meritum calculates this premium automatically based on the community code of your practice location; you do not need to look it up or apply it yourself.

## Why the RRNP exists

Alberta Health created the RRNP to attract and retain physicians in communities that would otherwise struggle to recruit. Rural, remote, and northern communities face higher costs, fewer locum options, and greater distances from specialist support. The RRNP premium compensates for these challenges by increasing the effective reimbursement for services provided in those communities.

The program is separate from other rural incentive programs like the Rural Remote Northern Program for medical residents or the Rural Physician Action Plan. The RRNP premium discussed here applies specifically to fee-for-service claims submitted through AHCIP.

## How eligibility is determined

RRNP eligibility is based on where you provide care, not where you live. Each community in Alberta is identified by a community code in the AHCIP reference data. Alberta Health maintains a list of community codes that qualify for RRNP premiums, along with the percentage rate assigned to each one.

When you configure a practice location in Meritum, you enter the community code for that facility. If the community code matches an entry in the RRNP rate table, all claims billed from that location automatically receive the RRNP premium. If you work at multiple locations, some may qualify and others may not. The premium applies per claim based on the location you select when creating the claim.

A physician who practises three days a week in an RRNP-eligible community and two days in Edmonton would receive the premium only on claims from the eligible location.

## Premium rates

RRNP premium rates range from 7% to over 30%, depending on the community. Communities that are more remote or have greater difficulty attracting physicians receive higher rates. Alberta Health sets the rates and publishes them in the RRNP rate schedule.

The rate applies as a percentage of the base fee for the Health Service Code (HSC) on the claim. For example, if you bill a service with a base fee of $100.00 and your community qualifies for a 15% RRNP premium, the premium adds $15.00 to the claim, making the submitted amount $115.00 before any other modifiers or premiums.

The RRNP premium is calculated independently from other premiums. If a claim also qualifies for a Comprehensive Medical General Practitioner (CMGP) premium or an after-hours premium, each is calculated separately and then summed. The RRNP premium does not compound with other modifiers.

## How Meritum handles RRNP

The RRNP is classified as an implicit modifier in Meritum. This means it is applied automatically by the platform rather than requiring you to select it manually. The calculation happens when you create or validate a claim:

1. You select the practice location where you provided the service.
2. Meritum looks up the community code for that location.
3. If the community code appears in the RRNP rate table, the platform retrieves the current percentage rate.
4. The premium is calculated against the base fee and added to the claim total.
5. The fee breakdown on the claim detail page shows the RRNP premium as a separate line item so you can verify it before submission.

If your location does not qualify, no premium is applied and no RRNP line item appears.

## Rate updates

Alberta Health updates RRNP rates periodically, typically on an annual cycle. When rates change, Meritum loads the updated rate table with effective dates. Claims are always calculated using the rate that was in effect on the date of service, not the date you enter the claim. If you are submitting claims that span a rate change, the platform applies the correct rate to each claim based on its individual service date.

## Checking your eligibility

To confirm whether your practice location qualifies for RRNP, check the community code assigned to your location in Meritum. If the community is in the RRNP rate table, the platform will display the applicable percentage when you view or edit the location. You can also verify your community's RRNP status by consulting the Alberta Health RRNP rate schedule, which is published on the Alberta Health website.

If you need to add or update a practice location, see [Configuring your practice locations](/help-centre/getting-started/configuring-your-practice-locations).
