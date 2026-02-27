---
title: "Business arrangements in Alberta"
category: billing-reference
slug: business-arrangements-in-alberta
description: "What Business Arrangement numbers are, how they link physicians to Alberta Health payment streams, and common BA scenarios."
priority: 3
last_reviewed: 2026-02-25
review_cycle: quarterly
type: reference
---

A Business Arrangement (BA) number is the identifier that links your billing activity to a specific payment arrangement with Alberta Health. Every claim you submit through the Alberta Health Care Insurance Plan (AHCIP) is filed under a BA number, and that number determines where Alberta Health sends payment and assessment results. If you are setting up Meritum for the first time, you will enter your BA number during onboarding; see [Adding your business arrangement numbers](/help-centre/getting-started/adding-your-business-arrangement-numbers) for the step-by-step process.

## What a BA number represents

A BA number is not the same as your practitioner ID or billing number. Your practitioner ID identifies you as an individual physician. Your BA number identifies the billing arrangement under which your claims are paid. It is tied to a specific functional centre, payment method (cheque or electronic funds transfer), and pay-to entity (you personally, a professional corporation, or a clinic).

A single physician can hold more than one BA number if they participate in different billing arrangements. Most fee-for-service (FFS) physicians have one. Physicians in the Primary Care Panel and Continuity Model (PCPCM) hold two. The maximum in Meritum is two active BAs per physician at any time.

## BA holders and submitters

Two distinct roles are involved in electronic billing:

- **BA holder**: the physician or entity that owns the billing arrangement with Alberta Health. The BA holder is responsible for the claims filed under that number and receives payment.
- **Submitter**: the accredited entity that transmits claims electronically to Alberta Health on behalf of the BA holder. Meritum is your submitter.

These roles are separate because Alberta Health requires that electronic claim submissions come through an accredited submitter. You cannot transmit claims directly to the H-Link system yourself; an accredited submitter must do it on your behalf. The AHC11236 Submitter Authorization form is what formally links your BA number to Meritum as your submitter, giving Meritum permission to file claims under your BA.

This distinction matters when you change submitters. If you previously used a different billing agent or clinic-based submission system, you need to submit a new AHC11236 to authorize Meritum. Your BA number stays the same; only the submitter authorization changes.

## Setting up a new BA

If you are establishing a new billing arrangement with Alberta Health (for example, when starting independent practice), the process involves two steps:

1. **Register the BA with Alberta Health.** Contact Alberta Health to set up your Business Arrangement. They will assign a BA number and associate it with your practitioner ID, payment method, and pay-to entity.
2. **Authorize your submitter.** Once you have a BA number, complete the AHC11236 Submitter Authorization form to link it to Meritum. During onboarding, Meritum pre-fills this form with your details so you only need to print, sign, and mail or fax it to Alberta Health.

Alberta Health typically processes the AHC11236 within two to four weeks. While your BA is pending, you can create and validate claims in Meritum, but you cannot submit batches until the BA status moves to Active.

## Common BA scenarios

**Solo practitioner with one BA.** This is the most straightforward setup. You hold a single FFS BA number, and all your claims are submitted under it. One AHC11236 form, one payment stream.

**PCPCM physician with two BAs.** If you participate in PCPCM, you hold two BA numbers: one for PCPCM capitation and in-basket claims, and one for regular FFS out-of-basket claims. Meritum routes each claim to the correct BA automatically based on the Health Service Code's basket classification. Both BAs are submitted in the same weekly cycle, and each requires its own AHC11236. For details on how dual-BA routing works, see [PCPCM: Primary Care Panel and Continuity Model](/help-centre/billing-reference/pcpcm-primary-care-panel-and-continuity-model).

**Locum billing under another physician's BA.** When you work as a locum at another physician's practice, you may bill under their BA number rather than your own. In this scenario, the host physician's BA is the billing identity and payment goes to their arrangement. Meritum supports locum billing by letting you associate with a host physician's BA for specific locations or time periods, while keeping your own BA active for your regular practice.

**Changing practices.** If you move from one clinic to another or transition from a group billing arrangement to independent billing, your BA number may change, or you may keep the same number and update the submitter authorization. The key step is ensuring your AHC11236 is current: if Meritum is your new submitter, you need a new AHC11236 linking your BA to Meritum. If you are keeping the same submitter but changing payment details, that update happens through Alberta Health directly.

## BA status in Meritum

Meritum tracks the status of each BA on your account:

- **Pending**: you have entered the BA number and downloaded the AHC11236, but Alberta Health has not yet processed the authorization. You can create claims but not submit batches.
- **Active**: Alberta Health has confirmed the submitter link. Batch submission is available.

You can view and manage your BA status in your account settings under Business Arrangements. If your BA has been pending for more than four weeks, contact Alberta Health to check on the status of your AHC11236.
