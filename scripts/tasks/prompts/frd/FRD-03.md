# Task FRD-03: Update Domain 9 (Notification Service) FRD

## Objective

Update the Domain 9 Notification Service FRD to reflect the actual implementation. Also reconcile with the Domain 3 FRD (both cover notifications). The implementation lives in a single `notification/` module.

## Step 1: Read Current FRDs

Read both notification FRDs:
- `docs/frd/extracted/Meritum_Domain_09_Notification_Service.md` (primary — this is the file to update)
- `docs/frd/extracted/Meritum_Domain_03_Notification_Service.md` (secondary — check for content not in Domain 9)

## Step 2: Read Implementation

**Domain module:**
- `apps/api/src/domains/notification/notification.routes.ts`
- `apps/api/src/domains/notification/notification.handlers.ts`
- `apps/api/src/domains/notification/notification.service.ts`
- `apps/api/src/domains/notification/notification.repository.ts`

**Shared schemas and constants:**
- `packages/shared/src/constants/notification.constants.ts`
- `packages/shared/src/schemas/notification.schema.ts`

**Database schema:**
- `packages/shared/src/schemas/db/notification.schema.ts` (if exists)

## Step 3: Read Supplementary Specs

**Mobile Companion v2 (shift-related notifications):**
- `docs/frd/extracted/Meritum_Mobile_Companion_v2.md`
  - Focus on: shift reminder events, missed billing alerts, reconciliation prompts

**Pricing Gap Closure (payment/subscription events):**
- `docs/frd/extracted/Meritum_Pricing_Gap_Closure_Spec.md`
  - Focus on: REFUND_PROCESSED events, early bird expiry warnings, practice invitation events

**IMA Legal Requirements (compliance events):**
- Read: `scripts/tasks/ima-legal-requirements.tasks`
  - Focus on: export window notification events (4 new events), IMA amendment notifications, breach notification events

## Step 4: Key Changes to Incorporate

1. **Reconcile Domain 3 and Domain 9** — If Domain 3 FRD has content not covered in Domain 9, merge it into the Domain 9 FRD. The implementation is a single module so the FRD should be consolidated.

2. **New event types** — Check `notification.constants.ts` for the full event catalogue. Known additions:
   - Shift reminder events (30 min before shift, configurable)
   - Missed billing alerts (unmatched encounters after reconciliation)
   - Reconciliation completion prompts
   - REFUND_PROCESSED after cancellation refund
   - Early bird expiry 30-day warning
   - Practice invitation sent/accepted/declined
   - Export window opening (30-day data portability period)
   - IMA amendment published (requires acknowledgement)
   - Breach notification to affected custodians

3. **Digest modes** — Check implementation for digest configuration (immediate, daily, weekly). The constants file may define additional digest modes.

4. **WebSocket implementation** — Verify the FRD accurately describes the WebSocket push mechanism for real-time in-app notifications.

5. **Delegate notification routing** — Verify the FRD describes how delegates receive notifications filtered by their permission set and physician context.

6. **Email delivery** — Verify Postmark integration details, template system, and the rule that no PHI appears in email bodies.

## Step 5: Write Updated FRD

Write the complete updated FRD to: `docs/frd/extracted/Meritum_Domain_09_Notification_Service.md`

### Format Rules

- Preserve existing section structure and formal writing style
- Consolidate any Domain 3 content that was missing from Domain 9
- Update the event catalogue with all implemented event types (check constants file for complete list)
- Add sections for new notification categories (shift, reconciliation, compliance, pricing lifecycle)
- Update data model with all implemented tables
- Update API contracts with all implemented endpoints
- Do not add TODO/TBD/placeholder content

When complete, output on its own line: [TASK_COMPLETE]
If blocked, output: [TASK_BLOCKED] reason: <explanation>
