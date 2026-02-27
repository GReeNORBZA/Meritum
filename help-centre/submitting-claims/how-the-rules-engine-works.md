---
title: "How the rules engine works"
category: submitting-claims
slug: how-the-rules-engine-works
description: "Explains how the rules engine validates claims against Alberta Health requirements and SOMB governing rules before submission."
priority: 1
last_reviewed: 2026-02-25
review_cycle: on-change
type: reference
---

The rules engine checks every claim against Alberta Health Care Insurance Plan (AHCIP) structural requirements, Schedule of Medical Benefits (SOMB) governing rules, and known rejection patterns before you submit. It runs automatically each time you save a claim, and the results appear instantly on the claim detail screen.

## What the rules engine checks

The engine evaluates roughly 105 deterministic rules across several categories. Each rule compares specific claim fields against reference data; there is no guesswork involved. If a rule condition is met, the engine flags the claim.

**Modifier eligibility.** The engine verifies that each modifier you apply is valid for the health service code (HSC) on the claim. For example, the Comprehensive General Practitioner Modifier (CMGP) is only permitted on a defined set of office visit codes. If you attach CMGP to a code that does not qualify, the engine flags it as an error.

**Visit limits (Governing Rule 3).** Some codes limit how many times you can bill the same patient within a period. The engine counts your prior claims for that patient and code combination and warns you when the limit is approaching or exceeded.

**Referral requirements (Governing Rule 8).** Specialist consultation codes require a referring practitioner billing number. If the referral field is empty on a consultation claim, the engine raises an error.

**90-day submission window.** AHCIP requires claims to be submitted within 90 calendar days of the date of service. The engine flags an error if the window has passed and a warning when the deadline is within seven days.

**Diagnostic code requirements.** Certain HSC categories require a diagnostic code. If the category demands one and none is present, the engine flags the claim.

**Modifier conflicts.** Some modifier combinations are mutually exclusive. If both are present, the engine catches the conflict before submission.

**Time-based code validation.** For codes that require a time component, the engine checks that the time spent field is present and falls within the valid range for that code.

**PCPCM routing.** If you are enrolled in the Patient's Medical Home / Comprehensive Care (PCPCM) stream, the engine validates that the claim routes to the correct business arrangement based on the HSC basket classification.

## Errors vs. warnings

The rules engine produces two severity levels:

**Errors** block submission. A claim with unresolved errors cannot move to the submission queue. You must fix every error before the claim will submit. Common examples: missing referral on a consultation code, expired 90-day window, invalid modifier for the HSC code.

**Warnings** do not block submission, but they signal that Alberta Health may reject the claim. You can choose to submit anyway, though doing so increases the chance of an assessment or rejection. Common examples: visit limit approaching for the patient, 90-day window closing within seven days, potential modifier conflict that depends on context the engine cannot verify.

The distinction matters. Errors represent conditions that will almost certainly cause rejection. Warnings represent conditions that might cause rejection depending on factors the engine cannot fully evaluate, such as clinical context or Alberta Health's internal adjudication logic.

## Common flags and how to resolve them

**"Modifier not eligible for this code."** Open the claim, remove the flagged modifier, or change the HSC code to one that permits it. Check the SOMB schedule for the list of eligible modifiers per code.

**"Referral required for consultation code."** Add the referring practitioner's billing number in the referral field. This applies to specialist consultation codes under Governing Rule 8.

**"Submission window expires in X days."** Submit the claim promptly. If the window has already closed, the claim cannot be submitted through AHCIP; you will need to contact Alberta Health directly about late submissions.

**"Visit limit reached for this patient and code."** Review your billing history for this patient. If you have already billed the maximum visits allowed under Governing Rule 3, the claim will likely be rejected. Consider whether a different code applies.

**"Diagnostic code required."** Add a valid diagnostic code to the claim. The engine checks that the code exists in the current ICD reference set.

## How the rules engine improves over time

The rules engine tracks how you interact with its flags. If you consistently dismiss a specific warning and then the claim gets rejected for exactly the reason the warning predicted, the engine increases that rule's priority for your future claims. This means the flag will appear more prominently next time.

Conversely, if you dismiss a particular rule five times in a row without any resulting rejections, the engine suppresses it; you will stop seeing that flag unless your rejection pattern changes. This keeps the flag list focused on issues that actually matter for your billing patterns and specialty.

New physicians start with default rule priorities based on their specialty. As you process claims over your first 50 or so submissions, the engine calibrates to your specific coding patterns and the codes you use most often.

For more detail on the different types of flags and how they appear on your claims, see [Understanding flags and suggestions on your claims](/help-centre/submitting-claims/understanding-flags-and-suggestions-on-your-claims). For information on the optional revenue and coding suggestions that appear alongside rules engine flags, see [How the advice engine works](/help-centre/submitting-claims/how-the-advice-engine-works).
