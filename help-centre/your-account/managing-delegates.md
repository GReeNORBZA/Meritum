---
title: "Managing delegates"
category: your-account
slug: managing-delegates
description: "Change delegate permissions, revoke access, add new delegates, and handle delegate handovers."
priority: 2
last_reviewed: 2026-02-25
review_cycle: on-change
type: procedural
---

You manage all delegate relationships from **Settings > Delegates**. Permission changes take effect immediately, and revoking access invalidates the delegate's session on the spot.

## Changing a delegate's permissions

1. Go to **Settings > Delegates** and find the delegate you want to update.
2. Click **Edit Permissions**.
3. Switch to a different preset (Full Access, Billing Only, View Only) or select **Custom** to toggle individual permissions.
4. Click **Save**. The new permissions apply immediately; the delegate does not need to log out and back in.

Every permission change is recorded in the audit trail with a timestamp and your identity as the physician who made the change.

## Revoking delegate access

1. In **Settings > Delegates**, find the delegate and click **Remove**.
2. Confirm the removal. The delegate's active session for your account is invalidated immediately; they lose access to your data the moment you confirm.

If the delegate also works with other physicians, only your relationship is affected. Their access to other physician accounts remains unchanged.

## Adding a new delegate

The process is the same as the initial invitation. Go to **Settings > Delegates**, click **Invite Delegate**, enter the new delegate's email address, choose a permission preset or configure custom permissions, and send the invitation. For the full walkthrough, see [Inviting a delegate](/help-centre/getting-started/inviting-a-delegate).

## Handling a delegate handover

When a delegate leaves and someone new takes over their responsibilities, there is no transfer function. Instead:

1. Revoke the departing delegate's access using the removal steps above.
2. Invite the new delegate with the appropriate permissions.

The new delegate starts with a clean slate. They do not inherit the previous delegate's session history or configuration. If you need the same permission set, note the departing delegate's permissions before removing them, then replicate those settings in the new invitation.

## Delegates who serve multiple physicians

A delegate can accept invitations from more than one physician. Each physician-delegate relationship carries its own independent permission set. A delegate might have Full Access under your account and View Only under another physician's account; the two are completely separate.

The delegate switches between physician contexts from their dashboard. Each context switch is logged, and permissions are enforced based on the active context. Changing the permissions you grant a delegate has no effect on what another physician has granted them.

For more on how delegate access interacts with data separation, see [Delegate access and data separation](/help-centre/security-compliance/delegate-access-and-data-separation).
