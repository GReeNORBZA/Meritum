---
title: "Managing your practice account"
category: your-account
slug: managing-your-practice-account
description: "How practice admins manage physician seats, invitations, and consolidated billing for a practice group in Meritum."
priority: 2
last_reviewed: 2026-02-25
review_cycle: annual
type: procedural
---

The practice account lets a single administrator manage billing and physician membership for a group of five or more physicians. This article covers what you can do as a practice admin and where the boundaries of that access lie.

## What the practice admin sees

When you log in as a practice admin, the **Practice Dashboard** shows:

- **Seats**: a list of physicians in your practice, including their name, email, date joined, and billing mode (practice-consolidated or individual early bird).
- **Invitations**: pending invitations you have sent, with their status and expiry date.
- **Consolidated invoice**: the practice-level invoice showing total seats billed through the practice, per-seat rate, billing frequency, and the next billing date.

You do not see individual physician claims, patient records, rejection rates, or revenue figures. Practice admin access is limited to membership and billing management.

## Adding a physician to your practice

1. Open **Practice Dashboard** and select **Invite Physician**.
2. Enter the physician's email address. They must already have a Meritum account or be willing to create one.
3. The physician receives an email invitation with a link that expires after seven days.
4. Once the physician accepts, they appear in your seat list. Their billing mode depends on whether they hold an active early bird subscription: if they do, they stay on their individual rate until it expires, then transition automatically to practice-consolidated billing.

A practice must maintain at least five active physicians. If a removal would drop you below five, Meritum warns you before proceeding.

## Removing a physician

1. In the **Seats** section, find the physician you want to remove and select **Remove**.
2. Confirm the removal. It takes effect at the end of the current calendar month; the physician retains access until then.
3. After removal, the physician's subscription reverts to an individual plan. Their claims, patients, and billing history remain theirs.

If the practice drops below five active physicians after a removal takes effect, the practice is dissolved at the end of that billing period. All remaining physicians transition to individual subscriptions.

## What practice admins cannot access

Practice admin permissions are strictly scoped. You can view seats, manage invitations, and review the consolidated invoice. You cannot access:

- Claims or claim history for any physician
- Patient records or Protected Health Information (PHI)
- Individual billing volumes, revenue, or analytics
- Rejection rates or assessment results

This boundary exists by design. Individual physician billing data is personal professional information, and Meritum enforces separation between practice administration and clinical data. Every action you take as a practice admin is logged in the platform audit trail.

For a detailed explanation of what practice admins can and cannot see, read [Practice admin access boundaries](/help-centre/security-compliance/practice-admin-access-boundaries).

## Editing practice settings

1. Open **Practice Dashboard** and select **Settings**.
2. You can update the **practice name** and switch between **monthly** and **annual** billing frequency.
3. Changes to billing frequency take effect at the next renewal date.

Only the practice admin can edit these settings. If you need to transfer the admin role to another physician, contact [Meritum support](/help-centre/your-account/understanding-your-subscription).
