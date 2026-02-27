---
title: "Delegate access and data separation"
category: security-compliance
slug: delegate-access-and-data-separation
description: "How Meritum enforces data boundaries between physicians when delegates access multiple accounts, including permissions, context switching, logging, and revocation."
priority: 3
last_reviewed: 2026-02-25
review_cycle: annual
type: reference
---

Every delegate relationship in Meritum carries its own independent permission set, and no delegate action can cross the boundary between one physician's data and another's. This article explains how those boundaries work at a technical level: how permissions are scoped, how context switching is enforced, what gets logged, and what happens when you revoke a delegate's access.

## Independent permission sets

When you invite a delegate, the permissions you grant apply only to your physician account. If the same delegate also works with another physician, that relationship has its own separate permission set configured by that physician. The two sets are completely independent; changing one has no effect on the other.

This means a delegate might have Full Access under your account and View Only under a colleague's account. The platform evaluates permissions based on the active physician context, never by combining or inheriting permissions from other relationships.

Certain permissions are permanently restricted for all delegates regardless of configuration. Delegates cannot manage other delegates, manage your subscription, export data in bulk, or view audit logs. These restrictions are enforced at the platform level and cannot be overridden. For the full setup process, see [Inviting a delegate](/help-centre/getting-started/inviting-a-delegate).

## Context switching

A delegate who serves multiple physicians sees a physician selector on their dashboard. To access your data, they must explicitly select your name and practice from this list. Each selection is a context switch that the platform records.

While working in your context, every request the delegate makes is scoped to your physician account at the database level. The platform does not allow a delegate to query, view, or modify data belonging to another physician within the same session or request. There is no search, filter, or URL that can return records from a different physician's account, even if the delegate has an active relationship with that physician. To access the other physician's data, the delegate must switch contexts first.

Context switches are instantaneous but explicit. The delegate clicks the physician selector, chooses a different practice, and the interface reloads with that physician's data. The previous physician's data is no longer accessible until the delegate switches back.

## What delegates can see by default

The three built-in permission presets control the scope of delegate access:

- **Full Access**: create, edit, and submit claims; manage patients; view analytics and reports.
- **Billing Only**: enter claims and look up patients. No access to reports, analytics, or practice settings.
- **View Only**: read-only access to claims and patients. Useful for auditors or administrative reviewers.

If you select **Custom**, you can toggle individual permissions on or off. For example, you might allow a delegate to create claims but not submit them, or to view patient records but not edit demographics. Permission changes take effect immediately; the delegate does not need to sign out and back in. For details on editing permissions after the initial invitation, see [Managing delegates](/help-centre/your-account/managing-delegates).

## Batch approval authority

Delegates with the `BATCH_APPROVE` permission can approve flagged claims in a batch before submission. This is a higher-trust permission intended for experienced billing clerks who review and approve claims on your behalf.

When a delegate approves a batch, the platform records the approval with both the delegate's identity and your physician context. You receive an in-app notification each time a delegate exercises batch approval authority, including the number of claims approved and the batch identifier. This gives you visibility into approvals happening under your account without requiring you to be present for every batch cycle.

If you do not want any delegate approving claims on your behalf, do not grant the `BATCH_APPROVE` permission. It is not included in any of the default presets; you must enable it explicitly through the Custom permission configuration.

## Audit logging for delegate actions

Every action a delegate takes is recorded in the audit trail with two pieces of identity: the delegate's own user account and the physician context they were operating in at the time. This dual-identity logging means you can answer questions like "what did this delegate do under my account" and "which physician context was active when this change was made."

Logged actions include claim creation and edits, patient record changes, batch approvals, context switches between physicians, and permission changes made to the delegate's access. The audit trail is append-only; neither you nor the delegate can modify or delete these records.

## Revoking delegate access

When you remove a delegate from **Settings > Delegates**, their active session for your physician account is invalidated immediately. They lose access to your data the moment you confirm the removal. If they are currently signed in and working in your context, their next action will fail and they will be redirected to their dashboard.

Revocation affects only your relationship with that delegate. If the delegate also works with other physicians, those relationships and sessions continue without interruption. The delegate receives a notification that their access to your account has been removed.

There is no grace period or soft removal. Revocation is instant and permanent; to restore access, you would need to send a new invitation. The original permission set is not preserved, so you would configure permissions from scratch on the new invitation.
