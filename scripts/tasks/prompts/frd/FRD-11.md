# Task FRD-11: Update Domain 10 (Mobile Companion) FRD

## Objective

Read the current Domain 10 FRD and the actual implementation, then update the FRD in-place. This domain was significantly expanded — fold in the entire Mobile Companion v2 spec (shift scheduling, encounter logging, Connect Care reconciliation).

## Step 1: Read Current FRD

Read the full file:
- `docs/frd/extracted/Meritum_Domain_10_Mobile_Companion.md`

## Step 2: Read Implementation

**Domain module (subdirectory structure):**

Repositories:
- `apps/api/src/domains/mobile/repos/ed-shifts.repo.ts`
- `apps/api/src/domains/mobile/repos/encounters.repo.ts`
- `apps/api/src/domains/mobile/repos/favourite-codes.repo.ts`
- `apps/api/src/domains/mobile/repos/shift-schedules.repo.ts`

Routes:
- `apps/api/src/domains/mobile/routes/mobile.routes.ts`
- `apps/api/src/domains/mobile/routes/shift.routes.ts`
- `apps/api/src/domains/mobile/routes/favourite.routes.ts`
- `apps/api/src/domains/mobile/routes/schedule.routes.ts`

Services:
- `apps/api/src/domains/mobile/services/ed-shift.service.ts`
- `apps/api/src/domains/mobile/services/encounter.service.ts`
- `apps/api/src/domains/mobile/services/favourite-codes.service.ts`
- `apps/api/src/domains/mobile/services/mobile-summary.service.ts`
- `apps/api/src/domains/mobile/services/quick-claim.service.ts`
- `apps/api/src/domains/mobile/services/rrule.service.ts`
- `apps/api/src/domains/mobile/services/shift-reminder.service.ts`
- `apps/api/src/domains/mobile/services/shift-schedule.service.ts`

**Shared constants:**
- `packages/shared/src/constants/mobile.constants.ts`

## Step 3: Read Supplementary Specs

**Mobile Companion v2 (this is the primary supplementary spec — fold it entirely):**
- `docs/frd/extracted/Meritum_Mobile_Companion_v2.md`
  - C1: Revised mobile role (shift scheduling primary for CC users, quick claim secondary)
  - C2: Shift scheduling with iCal RRULE recurrence, reminders, forgotten-shift handling
  - C3: PHN-based encounter logging (4 capture methods: barcode scan, quick search, manual PHN, last-4-digits)
  - C4: Connect Care import reconciliation (PHN+date+facility matching, 4 match categories)
  - C5: Connect Care onboarding (is_connect_care_user flag, mode switching)

## Step 4: Key Changes to Incorporate

1. **Subdirectory architecture** — Implementation uses repos/, routes/, services/ subdirectories. Document this.

2. **Shift scheduling with RRULE** — Entirely new:
   - `shift_schedules` table with iCal RRULE recurrence patterns
   - `rrule.service.ts` handles recurrence expansion
   - Schedule CRUD endpoints
   - Shift auto-creation from schedules

3. **Shift reminders** — `shift-reminder.service.ts`:
   - Configurable reminder timing (30 min default)
   - Forgotten-shift detection (schedule exists but no shift started)
   - Push notifications via notification service

4. **Encounter logging** — `encounters.repo.ts` and `encounter.service.ts`:
   - `ed_shift_encounters` table
   - 4 capture methods: wristband barcode scan, quick patient search, manual PHN entry, last-4-digits shorthand
   - Partial PHN support for rapid ED entry

5. **Connect Care reconciliation** — PHN+date+facility matching between shift encounters and SCC imports:
   - Full match: timestamp assigned from encounter
   - Unmatched SCC row: shift window inference
   - Unmatched encounter: missed billing alert
   - Shift-only: fallback to time window

6. **Connect Care user modes** — Dual-mode mobile experience:
   - CC users: shift scheduling primary, quick claim secondary
   - Non-CC users: quick claim primary (original Mobile Companion behavior)
   - Controlled by `is_connect_care_user` flag on provider profile

7. **Quick claim service** — `quick-claim.service.ts` for streamlined claim entry on mobile

8. **Mobile summary** — `mobile-summary.service.ts` for dashboard/summary view on mobile

9. **Favourite codes** — Verify the FRD documents physician-curated favourite codes with default modifiers per favourite.

10. **After-hours detection** — Check `mobile.constants.ts` for after-hours bracket definitions and how they integrate with shift data.

## Step 5: Write Updated FRD

Write the complete updated FRD to: `docs/frd/extracted/Meritum_Domain_10_Mobile_Companion.md`

### Format Rules

- Preserve existing section structure where applicable, but this will be a significant expansion
- Fold the entire Mobile v2 spec into the main FRD as new sections
- Clearly delineate CC-user vs non-CC-user behavior in the mobile role section
- Add sections for: shift scheduling/RRULE, encounter logging, reconciliation, shift reminders
- Update data model with all new tables (shift_schedules, ed_shift_encounters, modifications to ed_shifts)
- Update API contracts with all new endpoints
- Maintain the formal writing style with Design notes for architectural decisions
- Do not add TODO/TBD/placeholder content

When complete, output on its own line: [TASK_COMPLETE]
If blocked, output: [TASK_BLOCKED] reason: <explanation>
