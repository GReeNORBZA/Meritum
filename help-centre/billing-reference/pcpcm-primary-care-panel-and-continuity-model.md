---
title: "PCPCM: Primary Care Panel and Continuity Model"
category: billing-reference
slug: pcpcm-primary-care-panel-and-continuity-model
description: "How the PCPCM blended funding model works, including dual-BA setup, basket classification, claim routing, and panel enrolment tracking."
priority: 3
last_reviewed: 2026-02-25
review_cycle: quarterly
type: reference
---

The Primary Care Panel and Continuity Model (PCPCM) is a blended funding arrangement for Alberta primary care physicians. Instead of relying entirely on fee-for-service (FFS) billing, PCPCM combines capitation payments for enrolled patients with regular FFS claims for services that fall outside the capitation bundle. If you participate in PCPCM, your billing in Meritum works slightly differently from a pure FFS physician: you hold two Business Arrangement (BA) numbers, and the platform routes each claim to the correct one automatically.

## How PCPCM differs from pure FFS

Under pure FFS, every insured service you provide generates a claim, and Alberta Health pays the Schedule of Medical Benefits (SOMB) fee for that specific service. Your revenue is entirely claim-driven.

Under PCPCM, you still submit FFS claims for the services you provide, but a subset of those services is covered by a monthly capitation payment tied to the patients enrolled on your panel. Alberta Health pays you a per-patient amount each month for those enrolled patients, regardless of whether they visit you that month. The FFS claims you submit for capitated services serve as shadow claims: they are submitted for tracking and reporting purposes, but the payment comes through the capitation stream rather than the individual claim.

Services not covered by the capitation payment are billed as regular FFS claims and paid in the usual way.

## The dual-BA requirement

PCPCM physicians need two active BA numbers:

- **PCPCM BA**: receives capitation payments and shadow claims for in-basket services.
- **FFS BA**: receives standard FFS claims for out-of-basket services.

When you set up Meritum during onboarding, the wizard asks whether you participate in PCPCM. If you select yes, you enter both BA numbers. Meritum uses these to route claims at submission time. For the step-by-step setup, see [Adding your business arrangement numbers](/help-centre/getting-started/adding-your-business-arrangement-numbers).

Each Thursday submission cycle, Meritum assembles two separate batches for PCPCM physicians: one batch under your PCPCM BA (containing in-basket claims) and one under your FFS BA (containing out-of-basket claims). Both batches are transmitted to Alberta Health through H-Link in the same cycle.

## Basket classification and claim routing

The term "basket" refers to whether a Health Service Code (HSC) is covered by the PCPCM capitation payment or billed separately through FFS.

- **In-basket**: the HSC is covered by capitation. Claims with in-basket codes route to your PCPCM BA.
- **Out-of-basket**: the HSC is not covered by capitation. Claims with out-of-basket codes route to your FFS BA.
- **Facility**: the HSC is a facility-based service with its own routing rules.

Meritum determines the basket classification by looking up the HSC in the reference data, which tracks basket assignments published by Alberta Health. The classification that applies to a claim is based on the date of service, not the date you enter the claim; if Alberta Health reclassifies a code between quarters, the version in effect on the service date governs routing.

You do not need to select a BA or choose a routing path when creating a claim. Meritum reads the HSC, checks its basket classification, and assigns the claim to the correct BA automatically. The routing decision is visible on the claim detail page so you can confirm which BA will receive the claim before submission.

## Panel enrolment tracking

PCPCM capitation payments are based on the patients enrolled on your panel. Each enrolled patient is formally registered with Alberta Health as part of your PCPCM panel, and your monthly capitation amount reflects the size and composition of that panel.

Meritum tracks your panel enrolment data so you can see which patients are enrolled, when their enrolment started, and their current enrolment status. This information appears alongside regular patient records and helps you understand the relationship between your panel size and your capitation revenue. Enrolment changes (new enrolments, voluntary departures, panel transfers) flow through Alberta Health and are reflected in Meritum as updates are received.

## What this means for your weekly workflow

If you are a PCPCM physician, your day-to-day claim entry in Meritum looks the same as any other physician. You create claims, select HSCs, and attach modifiers as usual. The difference is behind the scenes: the platform checks each claim's basket classification and routes it to the appropriate BA without any extra steps from you.

At submission time, you see two batches in your queue instead of one. Both are submitted in the same Thursday cycle and assessed independently by Alberta Health. Assessment results come back separately for each BA, so you may see different outcomes for your in-basket and out-of-basket claims.

If you are unsure whether a specific HSC is in-basket or out-of-basket, check the claim detail page after entering the code. The basket classification and target BA are displayed before you queue the claim for submission.
