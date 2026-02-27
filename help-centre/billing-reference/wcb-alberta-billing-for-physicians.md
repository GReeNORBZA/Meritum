---
title: "WCB Alberta billing for physicians"
category: billing-reference
slug: wcb-alberta-billing-for-physicians
description: "How WCB billing works in Alberta, including form types, timing-based fee tiers, and differences from AHCIP."
priority: 3
last_reviewed: 2026-02-25
review_cycle: quarterly
type: reference
---

Workers' Compensation Board (WCB) Alberta billing is a separate payment system from the Alberta Health Care Insurance Plan (AHCIP). When you treat a patient for a workplace injury, you bill WCB directly rather than submitting through Alberta Health. The fees, forms, submission process, and payment cycle are all distinct from AHCIP fee-for-service billing.

## How WCB billing differs from AHCIP

Under AHCIP, you create claims using Health Service Codes and submit them through H-Link on a weekly Thursday cycle. WCB works differently in several important ways:

- **Submission pathway**: WCB uses its own Electronic Injury Reporting (EIR) system. You submit structured forms through the myWCB portal rather than through H-Link.
- **Fee calculation**: WCB fees are timing-based. How quickly you submit after seeing the patient determines how much you are paid. AHCIP fees are fixed per the Schedule of Medical Benefits (SOMB).
- **No bundling reductions**: AHCIP applies combination rules that reduce fees when you bill certain services together. WCB does not; each service is paid at its full rate.
- **No Thursday cycle**: WCB submissions are not batch-queued on a weekly schedule. You can submit forms as they are ready.
- **Different data requirements**: WCB forms require employer details, injury descriptions, work restrictions, and return-to-work plans. AHCIP claims do not.

## Contract types and role codes

Before you can bill WCB, you need a contract and role code registered with WCB Alberta. Your contract ID identifies your agreement type, and your role code identifies your practice category. Together, they determine which forms you can submit.

Common combinations include:

- **General Practitioner (GP)** under a general contract: can submit first reports, progress reports, invoices, supply invoices, and corrections.
- **Specialist (SP)** under a specialist contract: can submit consultation reports, invoices, supply invoices, and corrections.
- **Occupational Injury Service (OIS)** physicians: use OIS-specific variants of the first report and progress report forms with expanded clinical assessment fields.
- **Nurse Practitioner (NP)**: similar access to GPs but cannot submit supply invoices.

Your contract and role codes are part of your [WCB billing setup](/help-centre/getting-started/setting-up-wcb-billing) in Meritum.

## The eight WCB form types

WCB billing uses structured forms rather than simple claim lines. Each form type serves a specific clinical and administrative purpose.

1. **C050E: Physician First Report.** The initial report you submit when a patient first presents with a workplace injury. Covers clinical assessment, injury details, treatment plan, and return-to-work information. This is the most common starting point for a WCB claim.

2. **C050S: OIS Physician First Report.** The OIS variant of the first report. Includes expanded fields for pain scales, functional capacity, and detailed work restrictions. Only available to OIS physicians.

3. **C151: Physician Progress Report.** A follow-up report for ongoing treatment. Includes updated treatment plans, opioid management monitoring, and return-to-work status. Created as a continuation of a C050E or a prior C151.

4. **C151S: OIS Physician Progress Report.** The OIS variant of the progress report with expanded restriction and functional capacity fields. Created from a C050S or prior C151S.

5. **C568: Medical Invoice.** An invoice-only form for services that do not require a clinical report. Supports multiple service lines with date ranges. Available to most contract types.

6. **C568A: Medical Consultation Report.** Used by specialists to report consultation findings. Includes space for a consultation letter attachment. Available to specialists, orthopaedic surgeons, and anaesthesiologists.

7. **C569: Medical Supplies Invoice.** An invoice for medical supplies such as braces or supports. Created as a follow-up to a consultation report or invoice. Not available to nurse practitioners.

8. **C570: Medical Invoice Correction.** Corrects a previously submitted C568 invoice. Contains paired "was/should be" line items. Created only from an existing C568.

## Timing-based fee tiers

The most significant difference from AHCIP is that WCB pays different rates depending on how quickly you submit after seeing the patient. Earlier submission earns a higher fee.

WCB defines five timing tiers based on business days (Monday through Friday, excluding Alberta statutory holidays) after the date of examination:

1. **Same day**: submit on the date of service for the highest rate.
2. **Next business day**: a slightly lower rate.
3. **2 to 5 business days**: a reduced rate.
4. **6 to 14 business days**: a further reduction.
5. **15 or more business days**: the lowest rate.

The date of examination counts as day zero. Deadlines are measured from the following business day, and a 10:00 MT cutoff applies on the deadline day. The specific tier boundaries vary by form type; first reports have a tighter on-time window (3 business days) than progress and consultation reports (5 business days).

Meritum calculates your current timing tier automatically and shows you the deadline and potential fee difference on each pending form. The advice engine flags forms approaching a tier boundary so you can prioritize submission accordingly.

## What Meritum handles for you

Meritum captures all required WCB form data, validates each form against WCB rules (including contract and role permissions, required field cascades, and injury classification validation), and calculates your timing tier. The platform pre-fills fields from prior reports when you create follow-up forms and tracks your submission deadlines.

For a step-by-step walkthrough of the submission process, see [Submitting WCB claims](/help-centre/submitting-claims/submitting-wcb-claims). To configure your WCB contract and role codes, see [Setting up WCB billing](/help-centre/getting-started/setting-up-wcb-billing).
