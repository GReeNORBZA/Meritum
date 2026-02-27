---
title: "Configuring your practice locations"
category: getting-started
slug: configuring-your-practice-locations
description: "Add your practice locations during onboarding Step 4, including functional centre, facility number, and community code for RRNP eligibility."
priority: 1
last_reviewed: 2026-02-25
review_cycle: on-change
type: procedural
---

Each practice location you add tells the platform where you provide care. The functional centre code, facility number, and community code attached to a location determine which Alberta Health Care Insurance Plan (AHCIP) governing rules apply to your claims and whether you qualify for Rural and Remote Northern Program (RRNP) premiums. You configure your first location in Step 4 of the onboarding wizard.

## Adding a location

1. Enter a **location name**. This is a label for your own reference; use something you will recognize when selecting a location during claim entry (for example, "Hinton Family Clinic" or "Elk Point Hospital").
2. Enter the **functional centre code**. This is the AHCIP code that identifies the type and setting of your practice. The functional centre determines which Schedule of Medical Benefits (SOMB) governing rules the validation engine applies to claims billed from this location. For example, a hospital functional centre enables inpatient service codes that would not be valid in an office setting.
3. Enter the **facility number**. This is the Alberta Health facility identifier for the physical site where you practise.
4. Enter the **address** for the location: street, city, province, and postal code.
5. Enter the **community code**. This is the AHCIP code that identifies the community where the facility is located. Meritum validates your community code against the AHCIP reference data during onboarding.

After filling in all fields, click **Add Location**. The location appears in your list immediately.

## Setting a default location

One of your locations must be marked as the **default**. The default location is pre-selected when you create a new claim, so pick the one where you provide care most often. To set it, click **Set as Default** next to the location. If you only have one location, it becomes the default automatically.

## Working at multiple facilities

Physicians who work at more than one site can add as many locations as needed. This is common for locum physicians who move between facilities across different communities within a single month. Each location carries its own functional centre, facility number, and community code, so the correct governing rules apply regardless of where you provided the service.

When you create a claim, you select the location where the encounter took place. The platform uses that location's functional centre to validate the claim and its community code to calculate any applicable RRNP premium.

## RRNP eligibility

If a location's community code qualifies under the RRNP, Meritum automatically calculates the RRNP premium percentage for claims billed from that location. The premium is determined by the community's classification in the RRNP rate table and can range from 7% to over 30%, depending on the community. You do not need to look up the rate or apply it manually; the platform handles it when you select an RRNP-eligible location on a claim.

For a full explanation of how the program works and which communities qualify, see [RRNP: Rural and Remote Northern Program](/help-centre/billing-reference/rrnp-rural-and-remote-northern-program).
