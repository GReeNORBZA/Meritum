---
title: "AHCIP fee-for-service billing: how the system works"
category: billing-reference
slug: ahcip-fee-for-service-billing-how-the-system-works
description: "Overview of how Alberta's AHCIP fee-for-service billing system works, from claim creation through payment."
priority: 3
last_reviewed: 2026-02-25
review_cycle: quarterly
type: reference
---

Alberta Health Care Insurance Plan (AHCIP) is the provincial health insurance program that covers insured medical services for Alberta residents. Under fee-for-service (FFS) billing, you submit a claim for each insured service you provide, and Alberta Health pays you according to the fee listed in the Schedule of Medical Benefits (SOMB). This article explains how the pieces fit together.

## The core concept: one service, one claim

Every insured encounter produces a claim. When you see a patient in your office and perform a service listed in the SOMB, you create a claim that tells Alberta Health what you did, for whom, where, and when. Alberta Health reviews the claim against its rules, and if everything checks out, pays the fee listed in the SOMB for that service.

This is different from salary or capitation models where payment is not tied to individual encounters. In FFS billing, your revenue depends directly on the claims you submit.

## Health service codes and the SOMB

The SOMB is published by Alberta Health and contains over 6,000 Health Service Codes (HSCs). Each HSC represents a specific medical service: an office visit, a surgical procedure, a consultation, a diagnostic interpretation, and so on. Every HSC has a base fee, a description, and a set of rules governing when and how it can be billed.

When you create a claim in Meritum, you select the HSC that matches the service you performed. The platform pulls the current base fee from the SOMB automatically. You do not need to look up or enter fee amounts yourself.

The SOMB is updated quarterly by Alberta Health (April, July, October, and January). Meritum tracks these updates so that claims are always validated against the fee schedule that was in effect on the date of service. For more detail on how the SOMB is structured, see [Understanding the Schedule of Medical Benefits](/help-centre/billing-reference/understanding-the-schedule-of-medical-benefits).

## Modifiers and premiums

The base fee is the starting point, but the final submitted amount can be adjusted by modifiers and premiums.

**Modifiers** are codes you attach to a claim to indicate specific circumstances. Some modifiers increase the fee (for example, an after-hours premium), some decrease it, and some set it to zero (the TM modifier used for shadow billing under Alternative Relationship Plans). You can attach up to three modifiers per claim, and the SOMB defines which modifiers are valid for each HSC.

**Premiums** are additional amounts calculated on top of the base fee. Common premiums include the Comprehensive Medical General Practitioner (CMGP) premium for qualifying visits, after-hours premiums for services provided outside standard office hours, and the Rural and Remote Northern Program (RRNP) premium for physicians practising in eligible communities.

Meritum calculates submitted fees automatically based on the HSC, modifiers, and any applicable premiums. You can see the fee breakdown on the claim detail page before submission.

## Business Arrangement numbers

A Business Arrangement (BA) number is the billing identity Alberta Health assigns to you. It links your claims to a specific payment arrangement and functional centre. Most physicians have a single BA number, but some arrangements require more than one. For example, Physician Comprehensive Care Model (PCPCM) physicians typically hold two: one for capitated in-basket services and one for FFS out-of-basket services.

When you set up Meritum, you enter your BA number during onboarding. The platform uses it to route your claims correctly when assembling the weekly submission batch.

## Electronic submission via H-Link

AHCIP claims are submitted electronically through a system called H-Link, which is Alberta Health's secure claims transmission channel. You do not interact with H-Link directly; Meritum handles the connection, file formatting, and transmission on your behalf.

Every Thursday, the platform assembles your queued claims into H-Link formatted files (grouped by BA number), transmits them to Alberta Health, and reports the submission status back to you. Assessment results typically arrive on Friday, telling you which claims were paid, held, or refused.

For a detailed walkthrough of this weekly cycle, see [The Thursday submission cycle explained](/help-centre/billing-reference/the-thursday-submission-cycle-explained). For more on H-Link itself, see [H-Link: what it is and how electronic claims submission works](/help-centre/billing-reference/h-link-what-it-is-and-how-electronic-claims-submission-works).

## What happens to your claims

After submission, Alberta Health assesses each claim against its own validation rules. The result is one of three outcomes:

- **Paid**: the claim passed assessment. Payment follows Alberta Health's standard remittance schedule.
- **Held**: Alberta Health flagged the claim for review. A hold reason code explains why.
- **Refused**: the claim was rejected. A refusal code and explanation are displayed in Meritum so you can decide whether to correct and resubmit.

Meritum retrieves these results automatically and updates your claim statuses. You do not need to check a separate portal or download assessment files yourself.

## Key points for physicians new to self-billing

If you previously worked at a clinic that handled billing on your behalf, a few things are worth noting. You are now responsible for selecting the correct HSC for each service, attaching appropriate modifiers, and ensuring claims are queued before the Thursday cutoff. Meritum's validation engine and rules engine check your claims against SOMB governing rules and flag potential issues before submission, but the clinical accuracy of the code you select remains your responsibility. Building a habit of reviewing the claim queue before each Thursday cutoff keeps your submissions clean and your revenue predictable.
