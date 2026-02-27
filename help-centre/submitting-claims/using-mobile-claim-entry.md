---
title: "Using mobile claim entry"
category: submitting-claims
slug: using-mobile-claim-entry
description: "Log Alberta Health Care Insurance Plan claims from your phone during ED shifts or between patients using quick claim entry and favourite codes."
priority: 1
last_reviewed: 2026-02-25
review_cycle: on-change
type: procedural
---

You can log Alberta Health Care Insurance Plan (AHCIP) claims from your phone while you work. Mobile claim entry is designed for two scenarios: logging patients during an Emergency Department (ED) shift, and creating a quick one-off claim between appointments. Both produce draft claims that you review and submit from your desktop later.

Mobile claim entry supports AHCIP claims only. Workers' Compensation Board (WCB) claims require form fields and attachments that do not fit a mobile workflow; create those on desktop.

## ED shift workflow

The ED shift workflow lets you log each patient encounter as it happens so nothing gets missed during a busy shift.

1. Open the **Claims** page on your phone and tap **Start ED Shift**.
2. Select your ED location from your saved practice locations.
3. For each patient you see, tap **Log Patient**. Search by name or Personal Health Number (PHN), or select from your recent patients list.
4. Choose a health service code. Your favourite codes appear first for one-tap selection; tap **Search** to find other codes by number or description.
5. Add modifiers if needed. The platform suggests after-hours modifiers automatically based on the current time (see below), and you can toggle common modifiers like CMGP with a single tap.
6. Add an optional note, then tap **Save and Next** to move on to the next patient.
7. When your shift is done, tap **End Shift**. Meritum displays a summary showing every encounter you logged: patient, code, modifiers, and timestamp. Review it for anything you missed or need to correct.

All encounters from the shift are saved as draft claims. Open them on desktop to run full validation, resolve any flags, and queue them for your next Thursday submission.

## Quick claim entry

Quick claim entry is for a single claim outside of a shift context. It takes under 30 seconds when you use recent patients and favourite codes.

1. Tap **Quick Claim** from the Claims page.
2. Select a patient. Your 20 most recent patients appear at the top; use the search bar for anyone else.
3. Select a health service code from your favourites or search for one.
4. Toggle modifiers if applicable (CMGP, AFHR, NGHR, TM).
5. Tap **Save as Draft**.

The claim appears in your unsubmitted queue on desktop, ready for review just like a claim you [create manually](/help-centre/submitting-claims/creating-claims-manually).

## Favourite codes

Favourite codes are a curated list of the health service codes you use most often. Each favourite offers one-tap selection and can include default modifiers that apply automatically when you choose it.

You can save up to 30 favourite codes. When you first use mobile claim entry, Meritum seeds your favourites from your 10 most frequently billed codes; if you have no billing history yet, it uses defaults for your specialty. Edit your favourites at any time under **Settings > Favourite Codes** to add custom labels, reorder the list, or change default modifiers.

## After-hours auto-detection

When you log a claim during a shift, Meritum checks the current time against standard after-hours windows and suggests the appropriate modifier:

- **Weekday evenings (17:00 to 23:00)**: suggests the AFHR (after-hours) modifier.
- **Nights (23:00 to 08:00)**: suggests the NGHR (night) modifier.
- **Weekends and statutory holidays**: suggests the WKND (weekend) modifier.

The suggestion appears as a pre-selected toggle. You can accept it, remove it, or choose a different modifier. After-hours detection uses the timezone of the practice location you selected at the start of your shift.
