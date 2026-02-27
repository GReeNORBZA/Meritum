---
title: "Creating claims manually"
category: submitting-claims
slug: creating-claims-manually
description: "Step-by-step guide to creating an AHCIP claim using the manual claim entry form, from patient selection through validation."
priority: 1
last_reviewed: 2026-02-25
review_cycle: on-change
type: procedural
---

To create a claim manually, open the **Claims** page and click **New Claim**. The claim form walks you through each required field, validates your entries as you go, and saves the claim as a draft for your review before submission.

## Filling in the claim form

1. **Patient**: search by Personal Health Number (PHN) or by name. Start typing and select the patient from the results. If the patient does not exist yet, you can add them from the search dropdown without leaving the form.

2. **Health service code (HSC)**: search by code number or description. As you type, the autocomplete shows matching codes from the Schedule of Medical Benefits (SOMB) along with their fee values. When you select a code, the platform displays any applicable modifiers alongside it so you can see what options are available for that service.

3. **Date of service**: defaults to today. Select a past date if you are entering a claim retroactively. The date must fall within the Alberta Health Care Insurance Plan (AHCIP) submission window for your Business Arrangement (BA).

4. **Location**: defaults to your primary practice location. If you work at multiple locations, select the correct one from the dropdown. Each location maps to a functional centre and facility number on the submitted claim.

5. **Modifiers**: add up to three modifiers if the service requires them. The form shows which modifiers are compatible with your selected HSC code. Common modifiers include CMGP (comprehensive care), call-out codes, and time-based premiums.

6. **Diagnostic code**: enter the ICD-9 diagnostic code that best describes the reason for the encounter. Start typing the code or description to search. Some HSC codes require a diagnostic code; the form marks the field as required when that is the case.

7. **Referral practitioner**: if the HSC code's governing rules require a referring physician, this field becomes mandatory. Search by name or practitioner ID to select the referring physician.

8. Click **Save as Draft**.

## What happens after you save

When you save a claim, two things happen immediately:

**The claim enters Draft status.** It sits in your unsubmitted queue and is not yet part of any Thursday batch. You can edit or delete it freely at this point.

**The validation engine runs.** Meritum checks the claim against AHCIP structural rules, SOMB governing rules, and your billing history. Within a few seconds, the claim is classified as either:

- **Clean**: no issues found. Depending on your submission preferences, the claim may move to Validated status automatically or wait for your review.
- **Flagged**: the validation engine found one or more issues that need your attention.

## Errors versus warnings

Flagged claims can have two types of issues:

- **Errors** are problems that will cause AHCIP to refuse the claim. You must fix these before the claim can be queued for submission. Examples: a missing diagnostic code when one is required by the HSC governing rules, a date of service outside the valid submission window, or an invalid modifier combination.

- **Warnings** are potential issues that will not block submission but are worth reviewing. Examples: a health service code that is uncommon for the patient's age group, or a fee that looks higher than typical for that code. You can submit the claim with active warnings; the platform flags them so you can make an informed decision.

Open any flagged claim to see the specific errors and warnings listed on the claim detail page. For a full explanation of each flag type and how to resolve them, see [Understanding flags and suggestions on your claims](/help-centre/submitting-claims/understanding-flags-and-suggestions-on-your-claims).
