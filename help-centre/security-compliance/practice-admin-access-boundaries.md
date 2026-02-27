---
title: "Practice admin access boundaries"
category: security-compliance
slug: practice-admin-access-boundaries
description: "What the practice admin role can and cannot access, and how Meritum separates administrative functions from clinical data."
priority: 3
last_reviewed: 2026-02-25
review_cycle: annual
type: reference
---

The practice admin manages membership and billing for a group practice but has no access to individual physician clinical data. This separation is enforced at the platform level, not by convention, and cannot be bypassed through the interface or the API.

## What the practice admin role is

A practice admin is the person responsible for operational management of a practice group in Meritum. The role exists to handle administrative tasks that apply to the group as a whole: managing physician seats, sending and tracking invitations, reviewing consolidated billing, and maintaining practice-level settings. The admin is typically a physician within the group or a designated office manager, but the role carries the same access boundaries regardless of who holds it.

The practice admin role is not a clinical role. It does not grant access to any physician's patients, claims, assessments, or billing analytics. It operates in a separate area of the platform with its own dashboard and its own set of permissions that do not overlap with clinical functions.

## What the practice admin can do

The admin has access to the following operational functions:

- **View aggregate metrics**: the admin can see how many active physicians are in the practice, how many invitations are pending, and the total seat count. These are headcount numbers, not clinical data.
- **Manage subscriptions**: the admin controls the practice-level billing relationship, including switching between monthly and annual billing frequency, viewing the consolidated invoice, and seeing per-seat cost breakdowns. Payment history and upcoming renewal dates are visible here.
- **Manage physician membership**: the admin can invite new physicians to the practice, remove physicians (effective at the end of the current billing period), and view the status of outstanding invitations.
- **View system-wide audit logs**: the admin can access audit logs for the practice group. These logs record administrative actions such as invitation events, seat changes, subscription modifications, and practice settings updates. Audit log queries can be filtered by user, date range, IP address, and action type.
- **Edit practice settings**: the admin can update the practice name and billing frequency.

None of these functions expose patient-level or claim-level information. The admin sees operational data about who is on the platform and how the practice subscription is structured.

## What the practice admin cannot do

The admin role explicitly excludes access to clinical data. The following are never available to the admin:

- **Patient records**: the admin cannot view, search, or export any patient demographics, Personal Health Numbers (PHNs), or contact information belonging to any physician in the practice.
- **Claims and claim history**: the admin cannot see individual claims, claim statuses, submission batches, assessment results, or rejection details for any physician.
- **Revenue and billing analytics**: individual physician billing volumes, revenue figures, rejection rates, and performance analytics are not visible to the admin. Aggregate practice metrics are limited to seat counts and subscription totals.
- **Rules engine and advice engine output**: flags, suggestions, and coaching insights generated for individual physicians are not accessible from the admin dashboard.
- **Clinical audit trail entries**: while the admin can view administrative audit logs (seat changes, subscription events), they cannot view audit entries related to clinical actions such as claim state changes, patient record access, or delegate activity within a physician's account.

This is not a limitation of the interface; it is enforced at the database query level. Admin API requests are scoped to administrative data. There is no query path, URL, or parameter that would return clinical data to an admin session.

## The ADMIN_PHI_ACCESS permission

In specific, documented circumstances, a practice admin may need access to a physician's Protected Health Information (PHI); for example, when a physician is incapacitated and continuity of care requires another party to access their records. Meritum provides a controlled mechanism for this through the `ADMIN_PHI_ACCESS` permission.

This permission is not granted by default. It requires:

1. **Explicit physician consent**: the physician whose data would be accessed must grant consent through the platform. This is not a setting the admin can enable unilaterally.
2. **Logged activation**: when `ADMIN_PHI_ACCESS` is activated, the event is recorded in the audit trail with the admin's identity, the consenting physician's identity, and a timestamp.
3. **Logged usage**: every data access made under this permission is individually logged. The physician can review these entries in their own audit log at any time.

The permission can be revoked by the physician at any time, and revocation takes effect immediately. There is no standing access; the design assumes the admin does not have PHI access unless a physician has specifically granted it and has not revoked it.

## The design principle

Meritum separates administrative functions from clinical data access as a core architectural decision. The practice admin needs to know who is in the group and how billing works. They do not need to know what any physician billed, which patients they treated, or what assessments came back from Alberta Health Care Insurance Plan (AHCIP).

This separation serves two purposes. First, it limits the blast radius of a compromised admin account: an attacker who gains access to the admin role cannot reach PHI. Second, it aligns with the principle of least privilege under the Health Information Act (HIA); access to health information should be limited to what is necessary for the purpose at hand.

## Audit trail for admin actions

Every action the practice admin takes is recorded in the audit trail. This includes seat additions and removals, invitation events, subscription changes, practice settings edits, and any activation or use of `ADMIN_PHI_ACCESS`. These records are append-only and cannot be modified or deleted by the admin or by Meritum staff.

If your practice needs to demonstrate compliance with HIA access-tracking requirements, the admin audit trail provides a complete record of all administrative activity.

For details on managing your practice group, see [Managing your practice account](/help-centre/your-account/managing-your-practice-account). For a broader overview of security measures across the platform, see [How Meritum protects your data](/help-centre/security-compliance/how-meritum-protects-your-data).
