# Meritum_Domain_10_Mobile_Companion

MERITUM

Functional Requirements

Mobile Companion

Domain 10 of 13  |  Responsive Web MVP + Connect Care Revision

Meritum Health Technologies Inc.

Version 2.1  |  February 2026

CONFIDENTIAL

# Table of Contents

1. [Domain Overview](#1-domain-overview)
2. [Mobile App Role by User Context](#2-mobile-app-role-by-user-context)
3. [ED Shift Workflow](#3-ed-shift-workflow)
4. [Shift Scheduling](#4-shift-scheduling)
5. [PHN-Based Encounter Logging](#5-phn-based-encounter-logging)
6. [Connect Care Import Reconciliation](#6-connect-care-import-reconciliation)
7. [Quick Claim Entry](#7-quick-claim-entry)
8. [Favourite Codes](#8-favourite-codes)
9. [Mobile Summary Dashboard](#9-mobile-summary-dashboard)
10. [Mobile UI Specifications](#10-mobile-ui-specifications)
11. [Offline Queue (Phase 2)](#11-offline-queue-phase-2)
12. [Data Model](#12-data-model)
13. [API Contracts](#13-api-contracts)
14. [Security](#14-security)
15. [Testing Requirements](#15-testing-requirements)
16. [Open Questions](#16-open-questions)
17. [Document Control](#17-document-control)

---

# 1. Domain Overview

## 1.1 Purpose

The Mobile Companion domain specifies the mobile-optimised experience for Meritum. At MVP, this is a responsive web application — not a native iOS/Android app. The goal is to give physicians a usable billing workflow from their phone, particularly for ED shift logging and quick claim entry between patients.

The key insight driving this domain is that most physician billing happens in two contexts: (1) at a desk after clinic hours (desktop), and (2) on the move between patients or during shifts (mobile). The desktop experience (Domains 4–8) is feature-complete. This domain focuses on the subset of workflows that must work well on a phone screen.

For physicians who use Connect Care for clinical documentation, the mobile app's primary role shifts from billing data capture to shift timing context. The SCC extract provides all billing data (service codes, modifiers, diagnostic codes, patient details, facility, BA), but the one critical gap is clock time of service — the extract contains only the encounter date, not the time. The mobile app bridges this gap through shift scheduling, PHN-based encounter logging, and Connect Care import reconciliation.

## 1.2 Scope

- Responsive web design: all Meritum pages render usably on mobile viewports (360px–428px width)
- Dual-mode mobile experience: Connect Care users (shift-focused) vs standard users (claim-focused)
- ED shift workflow: start shift → log patients with timestamps → end shift → review and submit
- Shift scheduling with iCal RRULE recurrence, reminders, and forgotten-shift handling
- PHN-based encounter logging with 4 capture methods (barcode scan, quick search, manual PHN, last-4-digits)
- Connect Care import reconciliation (PHN-based matching across 4 match categories)
- Quick claim entry: patient search → code entry → save as draft (standard-mode primary)
- Favourite codes: physician-curated list of frequently used HSC codes for one-tap entry
- Mobile summary dashboard: lightweight KPI view for mobile home screen
- Notification centre: mobile-optimised notification feed and actions
- Offline queue (Phase 2): capture claims when offline, sync when connectivity restored

## 1.3 Out of Scope

- Native iOS/Android apps (Phase 2; responsive web covers MVP mobile use cases)
- Offline-first architecture (Phase 2; MVP requires connectivity)
- Full analytics dashboards on mobile (desktop-only; mobile shows KPI summary)
- WCB form entry on mobile (complex multi-section forms are desktop-only; mobile shows read-only WCB claim summary)
- Provider profile and settings management (desktop-only)
- SCC parser and import workflow (covered by Connect Care integration FRD)
- Intelligence Engine rules (Domain 7)

## 1.4 Design Principles

**Thumb-zone optimisation:** Primary actions in the bottom half of the screen. Navigation at the bottom.

**Minimal input:** Favour selection over typing. Code search with autocomplete. Patient selection from recent list. PHN capture via barcode scan where possible.

**Speed over completeness:** Mobile captures the essentials (patient, code, modifiers, time). Desktop handles review, validation details, and batch management.

**No feature parity with desktop:** Mobile is a companion, not a replacement. It excels at capture; desktop excels at review and management.

**Context-aware defaults:** The system adapts its default view based on the physician's Connect Care status, pre-populates shift details from schedules, and auto-detects after-hours eligibility.

## 1.5 Domain Dependencies

| Domain | Direction | Interface |
|--------|-----------|-----------|
| Domain 4.0: Claim Lifecycle Core | Produces → | Claims created from quick entry, shift logging, and reconciliation receive shift timestamps and modifier annotations |
| Domain 5: Provider Management | Consumed | Provider profile, BA assignments, facility locations, Connect Care flag (`is_connect_care_user`), delegate relationships |
| Domain 6: Patient Registry | Consumed | Patient PHN lookup for encounter matching, minimal patient creation from mobile |
| Domain 7: Intelligence Engine | Produces → | Tier A deterministic signals from shift data (bedside-contingent rules) |
| Domain 8: Analytics & Reporting | Produces → | Shift-level reporting data, mobile summary KPIs |
| Domain 9: Notification Service | Produces → | Shift reminder events, missed billing alerts, reconciliation prompts |
| Domain 2: Reference Data | Consumed | HSC code lookups, modifier validation, specialty-typical code lists for favourite seeding |
| Connect Care Integration | Consumed by | SCC import rows consumed during reconciliation matching |
| Domain 11: Onboarding | Consumed by | Connect Care flag set during onboarding |

## 1.6 Module Architecture

The mobile domain uses a subdirectory structure rather than the flat domain module pattern, reflecting the breadth of functionality:

```
domains/mobile/
├── repos/
│   ├── ed-shifts.repo.ts           # ED shift CRUD, aggregation, summary queries
│   ├── encounters.repo.ts          # Encounter logging within shifts
│   ├── favourite-codes.repo.ts     # Favourite codes CRUD, bulk operations
│   └── shift-schedules.repo.ts     # Recurring schedule CRUD, expansion tracking
├── routes/
│   ├── mobile.routes.ts            # Quick claim, patient, summary, sync placeholder
│   ├── shift.routes.ts             # Shift lifecycle, patient logging, encounters, inferred confirmation
│   ├── favourite.routes.ts         # Favourite codes CRUD and reorder
│   └── schedule.routes.ts          # Shift schedule CRUD and calendar materialisation
└── services/
    ├── ed-shift.service.ts         # Shift state machine, after-hours detection, Alberta holidays
    ├── encounter.service.ts        # PHN validation (Luhn), 4 capture methods
    ├── favourite-codes.service.ts  # HSC enrichment, modifier validation, auto-seeding
    ├── mobile-summary.service.ts   # KPI aggregation with rate-limited audit logging
    ├── quick-claim.service.ts      # Draft AHCIP claim creation, minimal patient creation
    ├── rrule.service.ts            # iCal RRULE expansion (WEEKLY, MONTHLY, BYDAY, INTERVAL)
    ├── shift-reminder.service.ts   # Scheduled reminder processing, follow-up detection
    └── shift-schedule.service.ts   # Schedule CRUD, calendar materialisation, inferred shift creation
```

> **Design note:** The subdirectory structure was chosen because the mobile domain spans multiple resource types (shifts, encounters, schedules, favourites, quick claims) that each require their own repository, routes, and service logic. A flat structure would result in excessively large files.

---

# 2. Mobile App Role by User Context

The mobile app detects the user's Connect Care status from their provider profile (`providers.is_connect_care_user`). Based on this flag, the mobile experience adapts its default view and feature emphasis.

## 2.1 Feature Availability by User Context

| Feature | Connect Care User | Non-Connect Care User |
|---------|-------------------|----------------------|
| **Shift scheduling** (§4) | PRIMARY — drives reminders, auto-context, timestamp inference | USEFUL — drives reminders |
| **Shift encounter logging** (PHN scan + timestamp) (§5) | PRIMARY — fills the SCC time gap, enables reconciliation | PRIMARY — timestamps for billing |
| **Quick claim entry** (§7) | NOT USED — SCC provides billing data | PRIMARY — manual billing capture |
| **Favourite codes** (§8) | NOT USED during shift — used for non-CC clinic days | PRIMARY |
| **Mobile patient creation** (§7) | NOT USED — patients come from SCC extract | USEFUL for new patients |
| **Recent patients** | USEFUL for reconciliation reference | PRIMARY |
| **Connect Care reconciliation** (§6) | PRIMARY | N/A |
| **Mobile summary** (§9) | PRIMARY | PRIMARY |

## 2.2 Mode Switching

- **Connect Care mode:** default view is shift-focused (upcoming shifts, active shift, recent reconciliation). Quick claim entry is accessible via a secondary menu item ("Non-CC Billing") for clinic days when Connect Care is not used.
- **Standard mode:** default view is claim-entry-focused (original Mobile Companion behaviour). Shift scheduling still available but not the default.

Transition between modes is seamless. Existing favourite codes and templates remain available in both modes.

## 2.3 Connect Care User Onboarding

During onboarding (Domain 11) or via provider settings, the physician indicates whether they use Connect Care for clinical documentation.

When `is_connect_care_user = true`: the system enables the simplified shift clock (Section 5), shows the "Connect Care Import" navigation item, and adjusts the mobile app's default view to shift-focused.

If the physician later enables Connect Care, the mobile app transitions gracefully. Existing favourite codes and templates remain available for non-CC clinic days.

If the physician disables Connect Care, the mobile app reverts to standard mode.

An in-app help article explains how to export "My Billing Codes" and "My WCB Codes" from Connect Care, linked from the import page and the help centre (Domain 13).

---

# 3. ED Shift Workflow

The ED shift workflow is the primary mobile use case. Emergency department physicians see 15–40 patients per shift and need to log encounters in real-time. Without Meritum, they typically jot notes on paper or a personal device and transcribe into their billing system later — a process that loses 10–20% of billable encounters.

## 3.1 Shift Lifecycle

| # | Step | Description |
| --- | --- | --- |
| 1 | Start Shift | Physician taps 'Start Shift'. Selects practice location (pre-filled from schedule or default). Records shift_start timestamp. ED shift session created with `status = 'ACTIVE'`, `shift_source = 'MANUAL'`. |
| 2 | Log Patient | For each patient encounter: select patient (search by PHN or name, or create new from minimal fields) OR scan wristband barcode (Connect Care mode). System records encounter timestamp automatically. |
| 3 | Add Code(s) | Select HSC code from favourites or search. Add modifiers. System pre-fills based on time of day (after-hours auto-detection) and code defaults. For CC users in encounter-only mode, this step is skipped — only PHN + timestamp captured. |
| 4 | Quick Notes | Optional free-text note for the encounter (e.g., 'laceration repair, 45 min'). Not transmitted in claim — for physician's review reference only. |
| 5 | Next Patient | Save and move to next patient. Encounter saved as draft claim (standard mode) or encounter log entry (CC mode) linked to the shift. Minimal taps to log the next encounter. |
| 6 | End Shift | Physician taps 'End Shift'. Records shift_end timestamp. Recalculates patient count and estimated value from linked claims. Shows shift summary: patient count, estimated total value, any flagged items. Status transitions to `ENDED`. |
| 7 | Review (Desktop) | Physician reviews shift claims on desktop at their convenience. Full validation, modifier review, AI Coach suggestions. Queue for submission. When all claims reviewed, shift status transitions to `REVIEWED`. |

## 3.2 Shift Session Data

Shift sessions are stored in the `ed_shifts` table. The Mobile Companion creates and manages these sessions:

| Field | Type | Description |
| --- | --- | --- |
| shift_id | UUID | Primary key |
| provider_id | UUID FK | FK to providers. Physician scoping enforced at repository layer. |
| location_id | UUID FK | FK to practice_locations. The ED facility. |
| shift_start | TIMESTAMPTZ | When the shift started |
| shift_end | TIMESTAMPTZ | When the shift ended (null while active) |
| patient_count | INTEGER | Number of patients logged during this shift. Atomically incremented via SQL `SET patient_count = patient_count + 1`. |
| estimated_value | DECIMAL(10,2) | Sum of expected fees for all claims in this shift. Recalculated from linked claims on shift end. |
| status | VARCHAR(20) | ACTIVE, ENDED, REVIEWED. State machine: ACTIVE → ENDED → REVIEWED. |
| shift_source | VARCHAR(20) | MANUAL (physician tapped Start) or INFERRED (created from schedule). Default MANUAL. |
| inferred_confirmed | BOOLEAN | Physician confirmed the inferred shift. NULL for MANUAL shifts. |
| schedule_id | UUID FK | Linked schedule entry. NULL for ad-hoc shifts. |
| created_at | TIMESTAMPTZ | Default now() |

**Constraints:**
- Partial unique index on `(provider_id) WHERE status = 'ACTIVE'` enforces maximum one active shift per physician at the database level.
- Indexes on `(provider_id, status)`, `(provider_id, created_at)`, and `(schedule_id)`.

## 3.3 After-Hours Auto-Detection

When a physician logs a patient encounter during an ED shift, the system automatically detects whether the encounter time qualifies for after-hours billing. Detection converts the encounter timestamp to Alberta local time (`America/Edmonton` timezone) and evaluates:

**Weekend/Statutory Holiday (WKND):** Saturday, Sunday, or any Alberta statutory holiday (all day). Alberta statutory holidays include: New Year's Day, Family Day (3rd Monday of February), Good Friday, Victoria Day (last Monday before May 25), Canada Day, Heritage Day (1st Monday of August), Labour Day (1st Monday of September), Truth and Reconciliation Day (September 30), Thanksgiving (2nd Monday of October), Remembrance Day (November 11), Christmas Day.

**Weekday Evening (AFHR):** 17:00–22:59 local time. Suggests AFHR modifier if the code is eligible.

**Weekday Night (NGHR):** 23:00–07:59 local time. Suggests NGHR modifier if eligible.

**Standard Hours:** Weekday 08:00–16:59 local time. No modifier suggested.

The auto-detection is a suggestion, not automatic application. The physician confirms during desktop review. On mobile, a subtle indicator shows 'after-hours eligible' on the logged encounter. HSC-specific eligibility for the modifier is checked separately against Reference Data when available.

> **Design note:** The after-hours detection uses `Intl.DateTimeFormat` with the `America/Edmonton` timezone to correctly handle MDT/MST transitions. Alberta statutory holidays are computed algorithmically including Easter (Anonymous Gregorian algorithm) for Good Friday calculation.

---

# 4. Shift Scheduling

## 4.1 Shift Schedule Entry

The physician can enter a recurring or one-off shift schedule via a calendar interface (mobile or desktop). Each scheduled shift captures:

- **Name:** Descriptive label for the schedule (e.g., "Foothills ED Tuesday/Thursday evenings")
- **Location:** Practice location / facility (FK to `practice_locations`, validated as belonging to provider)
- **Start time:** Shift start in HH:mm format
- **Duration:** Shift duration in minutes (minimum 30, maximum 1440)
- **Recurrence rule:** iCal RRULE string for recurring shifts; a single RRULE for one-off shifts

When `end_time < start_time` on the clock (e.g. 18:00 start, 02:00 end), the system interprets this as an overnight shift — the end time falls on the next calendar day. Duration is stored in minutes, and the RRULE service calculates the concrete end timestamp by adding duration to the start timestamp.

Schedules are editable and deletable (soft delete via `is_active` flag). Changes to future shifts do not affect past shift logs. A maximum of 20 active schedules per physician is enforced.

## 4.2 iCal RRULE Recurrence

The `rrule` column stores an iCal RRULE string per RFC 5545. The backend expands RRULE into concrete shift instances for a rolling 90-day window.

**Supported RRULE properties:**

| Property | Support | Example |
|----------|---------|---------|
| `FREQ` | WEEKLY, MONTHLY | `FREQ=WEEKLY` |
| `INTERVAL` | Any positive integer (default 1) | `INTERVAL=2` |
| `BYDAY` | SU, MO, TU, WE, TH, FR, SA | `BYDAY=TU,TH` |
| `UNTIL` | YYYYMMDD format | `UNTIL=20260531` |
| `COUNT` | Positive integer | `COUNT=12` |

**Example patterns:**

| Pattern | RRULE |
|---------|-------|
| Every Tuesday and Thursday | `FREQ=WEEKLY;BYDAY=TU,TH` |
| Every weekday | `FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR` |
| Every other Monday | `FREQ=WEEKLY;INTERVAL=2;BYDAY=MO` |
| First and third Saturday of month | `FREQ=MONTHLY;BYDAY=1SA,3SA` |
| 12 occurrences starting March 1 | `FREQ=WEEKLY;BYDAY=MO;COUNT=12` |

> **Design note:** The RRULE expansion engine is implemented as a pure function service (`rrule.service.ts`) that supports `FREQ=WEEKLY` and `FREQ=MONTHLY` with `BYDAY`, `INTERVAL`, `UNTIL`, and `COUNT`. Full RFC 5545 RRULE support (e.g., `BYMONTHDAY`, `BYSETPOS`, `EXDATE`) is not implemented — the supported subset covers practical physician shift patterns. The expansion function returns concrete `ShiftInstance` objects with start and end `Date` values.

## 4.3 Calendar Materialisation

The schedule calendar endpoint expands all active RRULE schedules for a requested date range and returns concrete shift instances sorted by start time. Each instance includes:

- `start`: Concrete shift start timestamp
- `end`: Concrete shift end timestamp
- `date`: The RRULE-expanded date (YYYY-MM-DD)
- `scheduleId`: Source schedule identifier
- `scheduleName`: Schedule display name
- `locationId`: Facility for this shift

The calendar is visible on both mobile and desktop, showing upcoming shifts with facility labels.

## 4.4 Shift Reminders

The system sends reminders before each scheduled shift via the notification service (Domain 9):

**Pre-shift reminder:** Fires `SHIFT_REMINDER_BEFORE_MINUTES` (default: 15 minutes) before shift start. The reminder processor expands each active schedule's RRULE for a 2-day window around the current time and checks which instances fall within the reminder window.

Content: "Your ED shift at {Facility} starts at {time}. Tap to start shift logging."

Tapping the reminder opens the mobile app directly to the "Start Shift" screen with facility pre-populated from the schedule.

**Follow-up reminder:** If the physician does not start a shift within `SHIFT_REMINDER_BEFORE_MINUTES` after the scheduled start, a second notification fires (`SHIFT_FOLLOWUP_REMINDER`):

Content: "Your scheduled shift appears to have started. Would you like to begin tracking?"

The follow-up reminder processor checks whether the provider has an active shift; if so, the follow-up is suppressed.

| Event Type | Trigger | Priority |
|------------|---------|----------|
| `SHIFT_REMINDER` | `SHIFT_REMINDER_BEFORE_MINUTES` before scheduled start | HIGH |
| `SHIFT_FOLLOWUP_REMINDER` | `SHIFT_REMINDER_BEFORE_MINUTES` after scheduled start, if shift not started | HIGH |
| `SHIFT_INFERRED_PROMPT` | Import reconciliation finds inferred shift matches | MEDIUM |

## 4.5 Forgotten Shift Handling

When a physician has a scheduled shift but never taps "Start Shift":

1. The system creates an **implicit (inferred) shift record** based on the schedule:
   - `shift_start` = scheduled start time
   - `shift_end` = scheduled end time (computed from start + duration)
   - `location_id` = scheduled facility
   - `shift_source` = `'INFERRED'`
   - `inferred_confirmed` = `NULL` (pending physician confirmation)

2. When the Connect Care import arrives and contains claims with encounter dates matching the implicit shift's date AND the facility code matches: the claims are linked to the implicit shift.

3. The physician sees a reconciliation prompt: "You had a scheduled shift at {Facility} on {date} but didn't start shift logging. {N} claims from Connect Care match this shift. Apply shift times for after-hours modifier calculation?"

4. **If confirmed:** the system applies the scheduled shift window as the time-of-service range. All encounters within this window are eligible for AFHR/NGHR based on scheduled times. `inferred_confirmed` = `true`.

5. **If the physician started late** (e.g. tapped "Start Shift" at 19:00 for 18:00 scheduled start): the system uses the **earlier** of scheduled start and actual start for the shift boundary. Encounters in the gap are not lost.

The `createInferredShift` service function validates schedule ownership, checks no active shift exists, creates the shift record, and logs an audit event with `source: INFERRED`.

---

# 5. PHN-Based Encounter Logging

## 5.1 Context

For Connect Care physicians, the mobile encounter log captures **patient identity + timestamp** only. No service codes, modifiers, or diagnostic codes — the billing data comes from the SCC import. The mobile app's job is to record *who was seen and when*.

For non-Connect Care physicians, encounter logging within a shift includes patient selection, service code, modifiers, and timestamp — creating a draft claim linked to the shift.

## 5.2 Encounter Capture Methods

Four methods in order of preference (lowest friction first):

### 5.2.1 Method 1: Wristband Barcode Scan (BARCODE) — ~2 seconds

Hospital inpatients and ED registrations at AHS facilities receive a wristband with a barcode encoding their ULI (PHN).

- Physician points phone at patient's wristband.
- App decodes the barcode via device camera, extracts the PHN, validates format (9-digit Alberta with Luhn check, or out-of-province format).
- Records: PHN + current timestamp + active shift ID.
- Confirmation: brief haptic feedback + "Patient logged — {HH:MM}".
- No further input required. Physician moves to next patient.

Implementation: `BarcodeScanner.tsx` using the Web Barcode Detection API (or `zxing-js` polyfill for browsers without native support).

### 5.2.2 Method 2: Quick Patient Search (SEARCH) — ~5 seconds

For patients already in Meritum's registry (common for repeat patients at rural EDs):

- Physician taps "Log Encounter" and types 2–3 characters of patient last name.
- App shows matching patients from the physician's patient registry (scoped to `provider_id`).
- Physician taps the patient. PHN captured from existing record.
- Records: PHN + current timestamp + active shift ID.

Full 9-digit PHN is captured. Luhn validated.

### 5.2.3 Method 3: Manual PHN Entry (MANUAL) — ~10 seconds

For patients not yet in Meritum's registry and where scanning is unavailable:

- Physician taps "Log Encounter" and enters the PHN manually (numeric keypad).
- App validates format: exactly 9 digits, passes Luhn check digit validation.
- Records: PHN + current timestamp + active shift ID.

### 5.2.4 Method 4: Last-4-Digits Shorthand (LAST_FOUR) — ~5 seconds

For rapid logging in high-volume ED environments:

- Physician enters only the last 4 digits of the PHN.
- App validates: exactly 4 digits.
- Records: partial identifier + timestamp + shift ID + `phn_is_partial = true`.
- During reconciliation (Section 6), the last-4 match is resolved against full PHNs in the SCC import.
- Within a single shift, a 4-digit suffix is sufficient to disambiguate (the probability of two patients sharing the same last 4 digits in one ED shift is negligible).
- If an ambiguous match occurs (two patients with same last 4 digits in same shift), the reconciliation step prompts the physician to clarify.

## 5.3 PHN Validation

PHN validation is implemented as a service-layer function that validates based on capture method:

- **BARCODE / SEARCH / MANUAL:** Full 9-digit PHN required. Must pass Luhn check digit validation. PHN is optional for BARCODE/SEARCH/MANUAL methods (encounter can be logged without PHN if needed).
- **LAST_FOUR:** Exactly 4 digits required. Marked as partial (`phn_is_partial = true`).

Invalid PHN format returns a `422 PHN_VALIDATION_ERROR` response.

## 5.4 Encounter Data Model

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| encounter_id | UUID | No | Primary key |
| shift_id | UUID FK | No | Parent shift |
| provider_id | UUID FK | No | Physician (redundant with shift, but enforces scoping at query level) |
| phn | VARCHAR(9) | Yes | Full PHN or last-4 shorthand |
| phn_capture_method | VARCHAR(20) | No | BARCODE, SEARCH, MANUAL, LAST_FOUR |
| phn_is_partial | BOOLEAN | No | True if only last 4 digits captured. Default false. |
| health_service_code | VARCHAR(10) | Yes | HSC code (populated for non-CC encounters, null for CC encounter-only mode) |
| modifiers | JSONB | Yes | Array of modifier codes |
| di_code | VARCHAR(10) | Yes | Diagnostic code |
| free_text_tag | VARCHAR(100) | Yes | Optional memory aid (bed number, initials). NOT PHI. Excluded from exports. |
| matched_claim_id | UUID FK | Yes | Populated during reconciliation. FK to claims. |
| encounter_timestamp | TIMESTAMPTZ | No | When physician scanned/entered — the inferred time of service |
| created_at | TIMESTAMPTZ | No | Default now() |

**Indexes:** `(shift_id)`, `(provider_id, created_at)`, `(phn)`, `(matched_claim_id)`

**Constraint:** Encounters can only be logged against active shifts. The repository validates shift status before insert.

## 5.5 Optional Free-Text Tag

Each encounter log entry has an optional `free_text_tag` field (bed number, initials, brief memory aid). This is **not** treated as PHI — it is at the physician's discretion and is excluded from exports and reports as a precaution.

---

# 6. Connect Care Import Reconciliation

## 6.1 Trigger

When a Connect Care CSV import is processed and the physician has an active, manual, or inferred shift for the same date and facility, the system performs PHN-based matching between the SCC import rows and the shift encounter log.

## 6.2 Matching Logic

The matching key is: **Patient PHN + Encounter Date + Facility Code**.

For each SCC import row:

1. Extract Patient ULI (PHN), Encounter Date, and Facility Code.
2. Query the shift encounter log for entries where:
   - `shift.date` matches the SCC Encounter Date
   - `shift.facility_id` matches the SCC Facility Code (resolved via facility code → location mapping)
   - `encounter.patient_phn` matches the SCC Patient ULI (full match), OR
   - `encounter.patient_phn` matches the last 4 digits of the SCC Patient ULI (if `phn_is_partial = true`)
3. On match: assign the encounter's `logged_at` timestamp to the SCC import row as the inferred time-of-service. Link the encounter to the created claim via `matched_claim_id`.
4. **Multi-row encounters** (multiple SCC rows for same patient on same date, e.g. multiple service codes): all rows receive the same timestamp from the single encounter log entry. This is correct — the physician saw the patient once and billed multiple codes.

## 6.3 Match Categories

After matching, each SCC row and each encounter log entry falls into one of four categories:

| Category | SCC Row | Encounter Log | Meaning | Handling |
|----------|---------|---------------|---------|----------|
| **FULL_MATCH** | Has matching encounter | Has matching SCC row | Timestamp assigned. Modifier inference possible. | Apply `inferred_service_time = encounter.logged_at`. Evaluate time-based modifier rules. |
| **UNMATCHED_SCC** | No matching encounter | — | Billing code exists but no shift timestamp. Physician didn't log this encounter. | If shift window entirely within one modifier bracket → apply modifier from shift window. If boundary-crossing → prompt physician for approximate time. If no shift → no inference. |
| **UNMATCHED_ENCOUNTER** | — | No matching SCC row | Physician logged seeing a patient but no billing code in SCC. Potential missed billing. | Surface as **missed billing alert**. Display timestamp and free-text tag. Physician can go back to SCC or create manual claim. |
| **SHIFT_ONLY** | Encounter date matches shift, no per-encounter log | — | No encounter logging during shift. Fall back to shift window. | If entirely after-hours → apply modifier. If boundary-crossing → prompt or apply conservative modifier. Encourage future logging. |

## 6.4 Handling Detail: Full Match

- Claim receives `inferred_service_time = encounter.logged_at`.
- Time-based modifier rules evaluate against this timestamp:
  - Weekday 17:00–23:00 → AFHR auto-applied (Tier A deterministic)
  - Any day 23:00–08:00 → NGHR auto-applied
  - Weekend/holiday → WKND auto-applied (already deterministic from date alone, but timestamp confirms)
- Import summary shows: "Timestamp {HH:MM} from shift log → after-hours modifier applied."

## 6.5 Handling Detail: Unmatched SCC Row

1. **If shift window entirely within one modifier bracket** (e.g. 22:00–06:00 = all NGHR): apply modifier based on shift window alone. No per-encounter timestamp needed.
2. **If shift window crosses modifier boundaries** (e.g. 15:00–23:00): prompt physician: "{N} claim(s) could not be matched to an encounter timestamp. Your shift crossed the after-hours boundary at 17:00. Was this encounter before or after 17:00?" Offer quick time picker defaulting to shift midpoint.
3. **If no shift exists at all** (physician didn't schedule or start a shift): no timestamp inference possible. Claim created without time-of-service metadata. Standard Tier C intel rules fire ("Consider after-hours modifier").

## 6.6 Handling Detail: Unmatched Encounter — Missed Billing Alert

This is one of the highest-value features of the reconciliation. Physicians missing even 1–2 encounters per shift at $30–100/encounter adds up to significant lost revenue over a month.

- Surface as a **missed billing alert** in the import summary: "You logged {N} encounter(s) during your shift that have no matching billing code in Connect Care. Did you forget to capture these in SCC?"
- Display timestamp and (if available) free-text tag for each unmatched encounter to aid recall.
- Physician can: (a) go back to Connect Care and add missing SCC entries, then re-import; or (b) create a manual claim directly in Meritum using the encounter timestamp.
- Notification event: `RECONCILIATION_MISSED_BILLING` (HIGH priority).

## 6.7 Handling Detail: Shift-Only

- Physician started (or has inferred) shift but never logged individual encounters.
- All SCC rows matching shift date + facility linked to the shift.
- Time-of-service inferred from shift window:
  - If entirely after-hours → auto-apply appropriate modifier.
  - If boundary-crossing → prompt or apply conservative (lower-value) modifier and flag for review.
- Missed billing detection not possible (no encounter log to compare).
- Import summary encourages future logging: "Logging encounters during your shift enables automatic after-hours modifier application and missed billing detection."

## 6.8 Reconciliation Summary Display

The following display is rendered after reconciliation completes:

```
Connect Care Import — 14 Feb 2026
  Source: My Billing Codes CSV
  SCC extract: 12 claims (10 patients)
  ED shift: 18:00–02:00 at Foothills ED (started manually)
  Encounter log: 11 patients scanned

  ✓ Matched: 9 patients (11 claims) — timestamps assigned
     • 5 claims: AFHR auto-applied (encounters 18:32–21:45)
     • 3 claims: NGHT auto-applied (encounters 22:15–01:30)
     • 3 claims: standard hours modifiers unchanged

  ⚠ Unmatched SCC rows: 1 patient (1 claim) — no encounter log
     • PHN ***456789, code 03.03A — shift was after-hours,
       AFHR applied based on shift window

  ⚠ Unmatched encounters: 2 patients — no SCC billing code
     • Scanned at 19:45 (tag: "bed 4") — missing from SCC?
     • Scanned at 23:30 (tag: "chest pain") — missing from SCC?

  Modifiers applied: 8 (5 AFHR, 3 NGHT)
  Estimated additional revenue from modifiers: $255.00

  [Confirm Import]  [Review Details]
```

## 6.9 Partial PHN Resolution

When an encounter was logged with only the last 4 digits (Method 4):

1. During matching, find all SCC rows where Patient ULI ends with the logged 4 digits.
2. **Exactly one match:** resolve automatically. Link encounter to claim.
3. **Zero matches:** partial PHN doesn't correspond to any patient in the import. Surface as unmatched encounter (possible missed billing, or patient billed under different provider).
4. **Multiple matches** (rare — two patients with same last 4 digits in one shift): prompt physician to select the correct patient from matching candidates, displaying patient name and encounter details from SCC extract to aid identification.

---

# 7. Quick Claim Entry

For clinic-based physicians (non-Connect Care primary use case) who want to log a claim between patients without opening a full desktop session.

## 7.1 Quick Entry Flow

**Select patient:** Recent patients list (last 20, ordered by most recent claim date_of_service). Search by PHN or name. Create new patient (first name, last name, PHN, DOB, gender — minimal fields via `mobilePatientSchema`).

**Select code:** Favourites list (one-tap). Search with autocomplete. Recent codes shown.

**Modifiers:** Modifier quick-toggle buttons for the most common modifiers (CMGP, AFHR, NGHR, TM, WKND — as defined in `QUICK_TOGGLE_MODIFIERS`). Full modifier list accessible via 'More'.

**Date of service:** Defaults to today. Selectable calendar picker for prior dates. Cannot be in the future (validated by Zod schema).

**Save:** Saves as draft AHCIP claim with `state = 'DRAFT'` and `source = 'mobile_quick_entry'`. No validation run on mobile (desktop handles full validation). Confirmation haptic/visual.

## 7.2 Quick Entry Constraints

- Quick entry creates AHCIP claims only. WCB claims require too many form fields for mobile entry.
- Claims saved from quick entry are in DRAFT state. Full validation and queue/submission happens on desktop.
- Diagnostic codes are optional on mobile quick entry. Physician adds them during desktop review.
- No batch management on mobile. Mobile is for capture; desktop is for review and submission.

## 7.3 Minimal Patient Creation

Patients created from mobile quick entry require only: `first_name`, `last_name`, `phn` (9 digits, regex validated), `date_of_birth` (ISO 8601 date), `gender` (MALE, FEMALE, OTHER). Full patient profile editing happens on desktop. Patient records created from mobile are available in the full patient registry (Domain 6).

---

# 8. Favourite Codes

Physicians bill a relatively small set of codes repeatedly. A GP might use 10–20 codes for 80% of their encounters. The favourite codes feature provides one-tap access to these codes on mobile.

## 8.1 Favourites Data Model

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| favourite_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers |
| health_service_code | VARCHAR(10) | No | HSC code |
| display_name | VARCHAR(100) | Yes | Physician's custom label (e.g., 'Standard office visit' instead of '03.04A'). Null = use official description. |
| sort_order | INTEGER | No | Display order in favourites list. Physician can reorder. |
| default_modifiers | JSONB | Yes | Array of modifiers to auto-select when this favourite is used. E.g., `['CMGP']` for complex visit code. |
| created_at | TIMESTAMPTZ | No | Default now() |

**Indexes:** Unique index on `(provider_id, health_service_code)` prevents duplicate favourites. Index on `(provider_id, sort_order)` for ordered retrieval.

**Constraints:** Maximum 30 favourites per physician (enforced at repository layer via count check before insert).

## 8.2 Favourites Management

- Add/remove favourites from mobile settings or during code search (star icon)
- Reorder via drag-and-drop on mobile
- Maximum 30 favourites (prevents list from becoming unwieldy)
- Default modifiers configurable per favourite (applied automatically on selection, removable)
- Favourites sync across mobile and desktop — changes on one appear on the other
- HSC code and modifier validation: adding a favourite validates that the HSC code exists in Reference Data (Domain 2) and that any default modifiers are known codes

## 8.3 Auto-Seeding

On first mobile use (when the favourites list is empty), the system auto-seeds:

1. **From claim history:** Query the physician's top 10 most frequently billed HSC codes. If results found, bulk-create as favourites with sort_order 1–N.
2. **From specialty defaults:** If no claim history exists, get the physician's specialty from their provider profile, then query specialty-typical codes from Reference Data. Bulk-create from specialty defaults (capped at 10).

Auto-seeding is triggered lazily on the first GET `/api/v1/favourites` call and is idempotent (skipped if favourites already exist).

## 8.4 Enriched Responses

Favourite code list responses are enriched with data from Reference Data (Domain 2): the official HSC description and the base fee from the fee schedule. This avoids additional client-side lookups.

---

# 9. Mobile Summary Dashboard

## 9.1 Summary KPI Payload

The mobile home screen displays a lightweight KPI summary fetched via a single API call:

| Metric | Description |
|--------|-------------|
| `todayClaimsCount` | Claims created today by this physician |
| `pendingQueueCount` | Claims in 'queued' state awaiting submission |
| `unreadNotificationsCount` | Unread notification count from Domain 9 |
| `activeShift` | Current active ED shift details (shiftId, shiftStart, patientCount, estimatedValue) or null |

All queries are provider-scoped. No PHI is returned — counts only, plus shift metadata.

All four queries execute in parallel for performance.

## 9.2 Audit Rate Limiting

The summary endpoint is called frequently (every time the physician opens the mobile home screen). To avoid audit log noise, summary view audit logging is rate-limited to a maximum of 1 log entry per 10 minutes per physician, using an in-memory timestamp cache.

---

# 10. Mobile UI Specifications

## 10.1 Supported Viewports

| Breakpoint | Viewport Width | Target Devices |
| --- | --- | --- |
| Mobile | 360px – 428px | iPhone SE through iPhone 16 Pro Max, Samsung Galaxy S series, Pixel |
| Tablet | 429px – 1024px | iPad Mini, iPad, Samsung Tab. Hybrid layout. |
| Desktop | 1025px+ | Full desktop experience. Not this domain's concern. |

## 10.2 Mobile Navigation

Bottom tab bar with 4 primary destinations:

| Tab | Icon | Destination |
| --- | --- | --- |
| Home | Dashboard icon | Mobile KPI summary: today's claims logged, pending queue count, unread notifications count. |
| Shift | Clock icon | ED shift workflow. Shows 'Start Shift' button or active shift status. For CC users, also shows upcoming scheduled shifts. |
| New Claim | Plus icon | Quick claim entry flow (standard mode) or "Log Encounter" (CC mode during active shift). |
| Notifications | Bell icon | Mobile notification feed with unread badge. |

Patient search and favourites are accessible from within the Shift and New Claim flows. Full menu (settings, analytics, profile) accessible via hamburger menu or account icon in header.

## 10.3 Mobile Performance Targets

| Metric | Target |
|--------|--------|
| Time to interactive | < 3 seconds on 4G connection (`TTI_TARGET_MS = 3000`) |
| Code search autocomplete | < 200ms response (`CODE_AUTOCOMPLETE_MS = 200`) |
| Patient search | < 500ms response (`PATIENT_SEARCH_MS = 500`) |
| Claim save | < 1 second round-trip (`CLAIM_SAVE_MS = 1000`) |
| Shift patient logging | < 5 taps from 'Log Patient' to 'Saved' for repeat patient + favourite code (`MAX_TAPS_SHIFT_LOG = 5`) |

---

# 11. Offline Queue (Phase 2)

Phase 2 adds offline claim capture for areas with poor connectivity (rural hospitals, remote communities). Architecture accommodations at MVP:

**Service worker registration:** Registered at MVP to cache static assets and enable fast reload. Not used for offline data at MVP.

**Local storage schema:** Data model for offline claims defined at MVP (same structure as draft claims). Not populated at MVP.

**Sync endpoint:** `POST /api/v1/sync/claims` endpoint defined at MVP. Returns 501 Not Implemented at MVP. No authentication required on this endpoint — client may call without valid session when reconnecting after offline period.

Phase 2 implementation: claims saved to IndexedDB when offline. Background sync job uploads to server when connectivity restored. Conflict resolution: server wins for claims modified on both client and server. Offline claims clearly marked in UI until synced.

---

# 12. Data Model

## 12.1 New Tables

### `shift_schedules`

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| schedule_id | UUID | No | Primary key (default random UUID) |
| provider_id | UUID FK | No | Physician who owns this schedule. FK to `providers(provider_id)`. |
| location_id | UUID FK | No | Linked practice location. FK to `practice_locations(location_id)`. |
| name | VARCHAR(100) | No | Descriptive label for the schedule |
| rrule | TEXT | No | iCal RRULE format for recurrence pattern |
| shift_start_time | VARCHAR(5) | No | Shift start time in HH:mm format |
| shift_duration_minutes | INTEGER | No | Shift duration in minutes |
| is_active | BOOLEAN | No | Soft delete. Default true. |
| last_expanded_at | TIMESTAMPTZ | Yes | Last time RRULE was expanded into instances |
| created_at | TIMESTAMPTZ | No | Default now() |
| updated_at | TIMESTAMPTZ | No | Default now() |

**Indexes:** `(provider_id, is_active)`

### `ed_shifts`

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| shift_id | UUID | No | Primary key (default random UUID) |
| provider_id | UUID FK | No | FK to `providers(provider_id)` |
| location_id | UUID FK | No | FK to `practice_locations(location_id)`. The ED facility. |
| shift_start | TIMESTAMPTZ | No | When the shift started |
| shift_end | TIMESTAMPTZ | Yes | When the shift ended (null while active) |
| patient_count | INTEGER | No | Number of patients logged. Default 0. |
| estimated_value | DECIMAL(10,2) | No | Sum of expected fees. Default 0. |
| status | VARCHAR(20) | No | ACTIVE, ENDED, REVIEWED. Default ACTIVE. |
| shift_source | VARCHAR(20) | No | MANUAL or INFERRED. Default MANUAL. |
| inferred_confirmed | BOOLEAN | Yes | Physician confirmed inferred shift. Default false. |
| schedule_id | UUID FK | Yes | Linked schedule entry. NULL for ad-hoc shifts. FK to `shift_schedules(schedule_id)`. |
| created_at | TIMESTAMPTZ | No | Default now() |

**Indexes:**
- Partial unique index: `(provider_id) WHERE status = 'ACTIVE'` — enforces one active shift per physician
- `(provider_id, status)` — active shift lookups
- `(provider_id, created_at)` — shift history listing
- `(schedule_id)` — schedule-based lookups

### `ed_shift_encounters`

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| encounter_id | UUID | No | Primary key (default random UUID) |
| shift_id | UUID FK | No | Parent shift. FK to `ed_shifts(shift_id)`. |
| provider_id | UUID FK | No | Physician. FK to `providers(provider_id)`. Redundant with shift but enforces scoping independently. |
| phn | VARCHAR(9) | Yes | Full PHN or last-4 shorthand. Encrypted at rest. |
| phn_capture_method | VARCHAR(20) | No | BARCODE, SEARCH, MANUAL, LAST_FOUR |
| phn_is_partial | BOOLEAN | No | True if only last 4 digits captured. Default false. |
| health_service_code | VARCHAR(10) | Yes | HSC code (null for CC encounter-only mode) |
| modifiers | JSONB | Yes | Array of modifier codes |
| di_code | VARCHAR(10) | Yes | Diagnostic code |
| free_text_tag | VARCHAR(100) | Yes | Optional memory aid. NOT PHI. Excluded from exports. |
| matched_claim_id | UUID FK | Yes | Populated during reconciliation. FK to `claims(claim_id)`. |
| encounter_timestamp | TIMESTAMPTZ | No | When physician scanned/entered |
| created_at | TIMESTAMPTZ | No | Default now() |

**Indexes:** `(shift_id)`, `(provider_id, created_at)`, `(phn)`, `(matched_claim_id)`

### `favourite_codes`

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| favourite_id | UUID | No | Primary key (default random UUID) |
| provider_id | UUID FK | No | FK to `providers(provider_id)` |
| health_service_code | VARCHAR(10) | No | HSC code |
| display_name | VARCHAR(100) | Yes | Physician's custom label. Null = use official description. |
| sort_order | INTEGER | No | Display order in favourites list |
| default_modifiers | JSONB | Yes | Array of modifiers to auto-select |
| created_at | TIMESTAMPTZ | No | Default now() |

**Indexes:**
- Unique index: `(provider_id, health_service_code)` — no duplicate favourites
- `(provider_id, sort_order)` — ordered retrieval

## 12.2 Modified Tables

### `providers` — New Columns

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| is_connect_care_user | BOOLEAN | No | Whether physician uses Connect Care. Default false. |
| connect_care_enabled_at | TIMESTAMPTZ | Yes | When Connect Care mode was first enabled. |

---

# 13. API Contracts

## 13.1 Shift Management

| Method | Endpoint | Description | Permission |
| --- | --- | --- | --- |
| POST | `/api/v1/shifts` | Start a new shift. Body: `{ location_id }`. Returns shift. | CLAIM_CREATE, PHYSICIAN role |
| GET | `/api/v1/shifts/active` | Get the active shift (if any). Returns 204 if none. | CLAIM_VIEW, PHYSICIAN role |
| POST | `/api/v1/shifts/{id}/end` | End the active shift. Returns shift + summary. | CLAIM_CREATE, PHYSICIAN role |
| GET | `/api/v1/shifts/{id}/summary` | Get shift summary: patient count, estimated value, claim list. | CLAIM_VIEW, PHYSICIAN role |
| GET | `/api/v1/shifts/{id}` | Get shift details including encounter log. | CLAIM_VIEW, PHYSICIAN role |
| GET | `/api/v1/shifts` | List recent shifts. Params: `limit` (1–50, default 10), `status` filter. | CLAIM_VIEW, PHYSICIAN role |
| POST | `/api/v1/shifts/{id}/patients` | Log patient encounter in shift (legacy, creates draft claim). | CLAIM_CREATE, PHYSICIAN role |
| POST | `/api/v1/shifts/confirm-inferred` | Confirm an inferred shift. Body: `{ schedule_id }`. | CLAIM_CREATE, PHYSICIAN role |

## 13.2 Encounter Logging

| Method | Endpoint | Description | Permission |
| --- | --- | --- | --- |
| POST | `/api/v1/shifts/{shiftId}/encounters` | Log an encounter. Body: `{ phn?, phn_capture_method, phn_is_partial?, health_service_code?, modifiers?, di_code?, free_text_tag?, encounter_timestamp? }`. | CLAIM_CREATE, PHYSICIAN role |
| GET | `/api/v1/shifts/{shiftId}/encounters` | List encounters for a shift. | CLAIM_VIEW, PHYSICIAN role |
| DELETE | `/api/v1/shifts/{shiftId}/encounters/{encounterId}` | Remove a logged encounter (e.g. accidental scan). | CLAIM_CREATE, PHYSICIAN role |

**POST `/api/v1/shifts/{shiftId}/encounters`** — Request:

```json
{
  "phn": "123456789",
  "phn_capture_method": "BARCODE",
  "phn_is_partial": false,
  "free_text_tag": "bed 4"
}
```

Response (201):
```json
{
  "data": {
    "encounterId": "uuid",
    "shiftId": "uuid",
    "providerId": "uuid",
    "phn": "123456789",
    "phnCaptureMethod": "BARCODE",
    "phnIsPartial": false,
    "encounterTimestamp": "2026-02-14T18:32:00.000Z",
    "freeTextTag": "bed 4",
    "createdAt": "2026-02-14T18:32:00.000Z"
  }
}
```

## 13.3 Shift Schedule Management

| Method | Endpoint | Description | Permission |
| --- | --- | --- | --- |
| GET | `/api/v1/mobile/schedules` | List shift schedules for authenticated provider. | CLAIM_VIEW, PHYSICIAN role |
| POST | `/api/v1/mobile/schedules` | Create a shift schedule (one-off or recurring). | CLAIM_CREATE, PHYSICIAN role |
| PUT | `/api/v1/mobile/schedules/{id}` | Update a shift schedule. | CLAIM_CREATE, PHYSICIAN role |
| DELETE | `/api/v1/mobile/schedules/{id}` | Soft-delete a shift schedule. | CLAIM_CREATE, PHYSICIAN role |
| GET | `/api/v1/mobile/schedules/calendar` | Get materialised shift instances for a date range. Query: `from` (YYYY-MM-DD), `to` (YYYY-MM-DD). | CLAIM_VIEW, PHYSICIAN role |

**POST `/api/v1/mobile/schedules`** — Request:

```json
{
  "location_id": "uuid",
  "name": "Foothills ED Tues/Thurs",
  "rrule": "FREQ=WEEKLY;BYDAY=TU,TH",
  "shift_start_time": "18:00",
  "shift_duration_minutes": 480
}
```

## 13.4 Favourite Codes

| Method | Endpoint | Description | Permission |
| --- | --- | --- | --- |
| GET | `/api/v1/favourites` | Get physician's favourite codes in sort order. Auto-seeds on first call if empty. | CLAIM_VIEW |
| POST | `/api/v1/favourites` | Add a favourite. Body: `{ health_service_code, display_name?, default_modifiers?, sort_order }`. | CLAIM_CREATE |
| PUT | `/api/v1/favourites/{id}` | Update favourite (display_name, default_modifiers, sort_order). | CLAIM_CREATE |
| DELETE | `/api/v1/favourites/{id}` | Remove favourite. | CLAIM_CREATE |
| PUT | `/api/v1/favourites/reorder` | Bulk reorder. Body: `{ items: [{ favourite_id, sort_order }] }`. Max 30 items. | CLAIM_CREATE |

## 13.5 Quick Claim & Mobile Utilities

| Method | Endpoint | Description | Permission |
| --- | --- | --- | --- |
| POST | `/api/v1/mobile/quick-claim` | Create draft AHCIP claim from mobile. Body: `{ patient_id, health_service_code, modifiers?, date_of_service? }`. | CLAIM_CREATE |
| POST | `/api/v1/mobile/patients` | Create minimal patient from mobile. Body: `{ first_name, last_name, phn, date_of_birth, gender }`. | PATIENT_CREATE |
| GET | `/api/v1/mobile/recent-patients` | Recent patients for quick entry. Params: `limit` (1–20, default 20). | PATIENT_VIEW |
| GET | `/api/v1/mobile/summary` | Lightweight KPI payload for home screen. | CLAIM_VIEW |

## 13.6 Reconciliation

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/claims/connect-care/reconcile` | Trigger reconciliation for an import batch against shift data. Body: `{ importBatchId }`. Returns reconciliation result. |
| GET | `/api/v1/claims/connect-care/reconcile/{batchId}` | Get reconciliation result for an import batch. |
| POST | `/api/v1/claims/connect-care/reconcile/{batchId}/confirm` | Confirm reconciliation. Applies timestamps, modifiers, and links encounters to claims. |
| POST | `/api/v1/claims/connect-care/reconcile/{batchId}/resolve-time` | Resolve timestamp for unmatched SCC rows. Body: `{ claimId, inferredServiceTime }`. |
| POST | `/api/v1/claims/connect-care/reconcile/{batchId}/resolve-partial` | Resolve ambiguous partial PHN match. Body: `{ encounterId, selectedPatientUli }`. |

**POST `/api/v1/claims/connect-care/reconcile`** — Response (200):

```json
{
  "data": {
    "importBatchId": "uuid",
    "shift": {
      "shiftId": "uuid",
      "startTime": "2026-02-14T18:00:00.000Z",
      "endTime": "2026-02-15T02:00:00.000Z",
      "facility": "Foothills ED",
      "shiftSource": "MANUAL"
    },
    "summary": {
      "totalSccRows": 12,
      "totalEncounters": 11,
      "fullMatches": 9,
      "unmatchedSccRows": 1,
      "unmatchedEncounters": 2,
      "shiftOnlyRows": 0,
      "modifiersApplied": { "AFHR": 5, "NGHT": 3 },
      "estimatedAdditionalRevenue": "255.00"
    },
    "fullMatches": [
      {
        "encounterId": "uuid",
        "claimIds": ["uuid1", "uuid2"],
        "loggedAt": "2026-02-14T18:32:00.000Z",
        "modifierApplied": "AFHR",
        "patientUliMasked": "***456789"
      }
    ],
    "unmatchedSccRows": [
      {
        "claimId": "uuid",
        "patientUliMasked": "***456789",
        "serviceCode": "03.03A",
        "resolution": "SHIFT_WINDOW_APPLIED",
        "modifierApplied": "AFHR"
      }
    ],
    "unmatchedEncounters": [
      {
        "encounterId": "uuid",
        "loggedAt": "2026-02-14T19:45:00.000Z",
        "freeTextTag": "bed 4",
        "alert": "No matching SCC billing code — possible missed billing"
      }
    ],
    "partialPhnResolutions": []
  }
}
```

## 13.7 Sync Placeholder (Phase 2)

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | `/api/v1/sync/claims` | Phase 2 offline sync placeholder. Returns 501 Not Implemented at MVP. |

---

# 14. Security

## 14.1 Authentication and Authorization

- All mobile/shift/schedule/encounter/favourite endpoints require active authentication (Lucia session).
- The sync placeholder (`POST /api/v1/sync/claims`) does not require authentication at MVP — client may call without valid session when reconnecting after offline period.
- Permission guards per route:

| Route Group | Permission Required | Additional Guard |
|-------------|-------------------|-----------------|
| Shift management (start, end, list, confirm) | `CLAIM_CREATE` or `CLAIM_VIEW` (read-only) | `PHYSICIAN` role required |
| Encounter logging | `CLAIM_CREATE` | `PHYSICIAN` role required |
| Shift schedules | `CLAIM_CREATE` or `CLAIM_VIEW` (read-only) | `PHYSICIAN` role required |
| Favourite codes | `CLAIM_CREATE` (write) / `CLAIM_VIEW` (read) | — |
| Quick claim, mobile patient | `CLAIM_CREATE` / `PATIENT_CREATE` | — |
| Mobile summary | `CLAIM_VIEW` | — |
| Reconciliation | `CLAIM_CREATE` | — |

- Delegates with appropriate permissions may manage favourites and create quick claims on behalf of their physician. Shift management and encounter logging require `PHYSICIAN` role (delegates cannot directly manage shifts).

## 14.2 Physician Tenant Isolation

- `shift_schedules`, `ed_shifts`, `ed_shift_encounters`, and `favourite_codes` are all scoped to `provider_id` at the repository layer.
- `ed_shift_encounters.provider_id` is redundant with `ed_shifts.provider_id` but is enforced independently to guarantee scoping even if the shift join is bypassed.
- A physician cannot view, modify, or access another physician's shift data, encounter logs, schedule data, favourite codes, or reconciliation results. Cross-provider access returns 404 (not 403 — do not confirm resource existence).

## 14.3 PHI Handling

- **Encounter log contains PHI** (PHN + timestamp). Subject to the same controls as all other PHI:
  - Encrypted at rest (PostgreSQL managed encryption, DigitalOcean Toronto).
  - PHN masked as `123******` in application logs.
  - Provider-scoped queries only.
- **Free-text tags are NOT treated as PHI** but are excluded from exports and reports as a precaution.
- **No PHI in push notifications or emails.** Shift reminders contain facility and time only, never patient data. Missed billing alerts reference encounter count and timestamps, never PHN.
- **Reconciliation responses mask PHN:** `patientUliMasked: "***456789"` in API responses. Full PHN available only in the linked claim record.
- **Error responses never echo PHN.** PHN validation errors return generic messages ("PHN failed Luhn check digit validation") without echoing the submitted value.

## 14.4 Audit Logging

| Audit Event | Trigger |
|-------------|---------|
| `mobile.shift_started` | Physician starts a shift (manual) |
| `mobile.shift_ended` | Physician ends a shift |
| `mobile.patient_logged` | Patient encounter logged (shift mode, any capture method) |
| `mobile.encounter_deleted` | Encounter removed |
| `mobile.quick_claim_created` | Quick claim created from mobile |
| `mobile.favourite_added` | Favourite code added (including auto-seeding) |
| `mobile.favourite_removed` | Favourite code removed |
| `mobile.favourite_reordered` | Favourites reordered |
| `mobile.summary_viewed` | Mobile summary viewed (rate-limited: max 1 per 10 min per physician) |
| `mobile.schedule_created` | New shift schedule created |
| `mobile.schedule_updated` | Schedule modified |
| `mobile.schedule_deleted` | Schedule soft-deleted |
| `mobile.inferred_shift_created` | System creates inferred shift from schedule |
| `mobile.shift_reminder_sent` | Pre-shift reminder notification emitted |
| `mobile.shift_followup_sent` | Follow-up reminder for unstarted shift emitted |
| `RECONCILIATION_EXECUTED` | Reconciliation performed for import batch |
| `RECONCILIATION_CONFIRMED` | Physician confirms reconciliation results |
| `RECONCILIATION_MISSED_BILLING` | Missed billing alert generated |
| `RECONCILIATION_PARTIAL_RESOLVED` | Partial PHN match resolved |
| `RECONCILIATION_TIME_RESOLVED` | Physician provides time for unmatched SCC row |

---

# 15. Testing Requirements

## 15.1 Responsive Design Tests

- All mobile-designated pages render correctly at 360px, 390px, and 428px widths
- No horizontal scroll on any mobile page
- Touch targets meet minimum 44x44px (WCAG)
- Bottom navigation tabs accessible with thumb in any hand position
- Text readable without zooming (minimum 16px body text)

## 15.2 Unit Tests

**Location:** `apps/api/src/domains/mobile/`

**ED Shift Service:**
- Start shift → validates location ownership → creates ACTIVE shift → audit logged
- Start shift with existing active shift → ConflictError
- End shift → recalculates patient_count and estimated_value from linked claims → status ENDED
- End non-active shift → BusinessRuleError
- Mark shift as REVIEWED from ENDED state
- After-hours detection: encounter at 18:32 weekday → AFHR bracket
- After-hours detection: encounter at 22:15 weekday → NGHR bracket (23:00+ boundary)
- After-hours detection: encounter on Saturday → WKND bracket
- After-hours detection: encounter on Alberta statutory holiday → WKND bracket
- After-hours detection: encounter at 10:00 weekday → null (standard hours)
- Log patient during active shift → creates draft claim, detects after-hours, increments counter

**Shift Scheduling:**
- Create schedule → validates location ownership → stored correctly → audit logged
- Update schedule → returns updated record → audit logged
- Delete schedule → soft delete (isActive = false) → audit logged
- List schedules for provider → returns provider's schedules only

**RRULE Expansion:**
- `FREQ=WEEKLY;BYDAY=TU,TH` → correct Tuesday/Thursday dates generated
- `FREQ=WEEKLY;INTERVAL=2;BYDAY=MO` → every other Monday
- `FREQ=MONTHLY;BYDAY=1SA,3SA` → first and third Saturday
- UNTIL constraint respected
- COUNT constraint respected
- Overnight shift (18:00 start, 480 min duration) → end time on next calendar day
- Invalid FREQ → Error thrown
- Invalid BYDAY → Error thrown

**Shift Reminders:**
- Scheduled shift in reminder window → `SHIFT_REMINDER` event generated
- Shift start time passed + lookback, no shift started → `SHIFT_FOLLOWUP_REMINDER` generated
- Physician starts shift before followup → no follow-up fired (has active shift)
- RRULE expansion error → error captured in result, processing continues for other schedules

**Forgotten Shift / Inferred:**
- Scheduled shift, no manual start → inferred shift record created with `shift_source = 'INFERRED'`
- Inferred shift from inactive schedule → BusinessRuleError
- Inferred shift when active shift exists → BusinessRuleError

**Encounter Logging:**
- Barcode scan with valid Alberta PHN → encounter created, `phn_capture_method = 'BARCODE'`
- Patient search → encounter created with full PHN from registry
- Manual entry with invalid Luhn → PhnValidationError
- Manual entry with non-9-digit PHN → PhnValidationError
- Last-4 shorthand → encounter created with `phn_is_partial = true`
- Last-4 with non-4-digit input → PhnValidationError
- Optional free_text_tag stored correctly
- Encounter without active shift → BusinessRuleError
- Delete encounter → returns deleted record → audit logged
- Delete non-existent encounter → EncounterNotFoundError

**Quick Claim Service:**
- Create quick claim → AHCIP draft claim with source 'mobile_quick_entry' → audit logged
- Date defaults to today when not provided

**Favourite Codes Service:**
- Add favourite with valid HSC → created, enriched with description and baseFee
- Add favourite with unknown HSC → ValidationError
- Add favourite with unknown modifier → ValidationError
- Add 31st favourite → BusinessRuleError (max 30)
- Add duplicate HSC for same provider → ConflictError
- Seed from claim history → top 10 codes bulk-created
- Seed from specialty defaults when no claim history → specialty codes bulk-created
- Seed when favourites already exist → returns 0 (idempotent)
- Reorder → updates sort_order → audit logged
- Reorder with favourite from another provider → BusinessRuleError

**Mobile Summary:**
- Returns correct counts for today's claims, pending queue, unread notifications
- Returns active shift details when shift is active
- Returns null activeShift when no shift active
- Audit logging rate-limited (second call within 10 min → no audit log)

**Reconciliation:**
- Full match (PHN + date + facility) → timestamp assigned, modifier evaluated
- Unmatched SCC row, shift entirely after-hours → modifier applied from shift window
- Unmatched SCC row, shift crosses boundary → prompt generated
- Unmatched encounter → missed billing alert generated
- Shift-only (no per-encounter logs) → fall back to shift window
- Multi-row encounter (same patient, multiple SCC rows) → all receive same timestamp
- Partial PHN (last 4), one match → auto-resolved
- Partial PHN, zero matches → unmatched encounter
- Partial PHN, multiple matches → prompt for disambiguation
- AFHR rule: encounter at 18:32 weekday → AFHR applied
- NGHR rule: encounter at 23:15 → NGHR applied

## 15.3 Integration Tests

**Location:** `apps/api/test/integration/mobile/`

- Start shift → log 3 patients with favourite codes → end shift → summary shows 3 patients
- Create schedule → start shift → log 3 encounters → end shift → verify shift record and encounters
- Schedule with RRULE → verify calendar endpoint returns correct instances
- Quick claim → draft claim created → appears in desktop claim list
- Patient created from quick entry → available in full patient registry
- Favourites auto-seeding on first GET → seeded from claim history or specialty defaults
- After-hours detection: shift starting at 18:00 → encounters flagged as after-hours eligible
- Active shift persists across page reload (GET active returns same shift)
- Only one active shift per physician at a time (second start → 409)
- Inferred shift creation → confirm → inferred_confirmed = true
- Upload SCC CSV → reconcile → full matches get timestamps → modifiers applied → claims updated
- Upload SCC CSV with no shift → no reconciliation, standard claim creation
- Missed billing alert → notification generated with HIGH priority

## 15.4 Security Tests

**Location:** `apps/api/test/security/mobile/`

### Authentication Enforcement (`mobile.authn.security.ts` / `mobile-v2.authn.security.ts`)
- Every shift, schedule, encounter, favourite, quick claim, summary, and reconciliation endpoint returns 401 without session

### Authorization (`mobile.authz.security.ts` / `mobile-v2.authz.security.ts`)
- Delegate without `CLAIM_CREATE` → 403 on shift start, quick claim
- Delegate without `CLAIM_VIEW` → 403 on favourites list, mobile summary
- Non-PHYSICIAN role → 403 on shift management, encounter logging, schedule management

### Tenant Isolation (`mobile.scoping.security.ts` / `mobile-v2.scoping.security.ts`)
- Physician 1's shifts not visible to Physician 2
- Physician 1's schedules not visible to Physician 2
- Physician 1's shift encounters not visible to Physician 2
- Physician 1's favourite codes not visible to Physician 2
- Physician 1's reconciliation results not accessible by Physician 2
- Physician 2 cannot log encounters on Physician 1's shift
- List endpoints return only authenticated provider's data

### Input Validation (`mobile.input.security.ts` / `mobile-v2.input.security.ts`)
- SQL injection in PHN field → blocked by Zod
- Invalid PHN format (non-numeric) → 400
- Invalid Luhn check digit → 422
- XSS in free_text_tag → sanitised or stored safely
- Non-UUID shift/encounter/favourite/schedule IDs → 400
- Invalid RRULE format → 400
- Negative shift_duration_minutes → 400
- shift_duration_minutes > 1440 → 400

### Data Leakage (`mobile.leakage.security.ts` / `mobile-v2.leakage.security.ts`)
- Encounter errors do not echo full PHN
- Reconciliation responses mask PHN (`***456789`)
- Shift reminder notifications contain no PHI
- 500 errors expose no internal details
- Response headers do not contain server version

### Audit Trail (`mobile.audit.security.ts` / `mobile-v2.audit.security.ts`)
- Shift start → `mobile.shift_started` audit entry
- Shift end → `mobile.shift_ended` audit entry
- Encounter logged → `mobile.patient_logged` audit entry with capture method
- Encounter deleted → `mobile.encounter_deleted` audit entry
- Schedule created → `mobile.schedule_created` audit entry
- Quick claim → `mobile.quick_claim_created` audit entry
- Favourite added → `mobile.favourite_added` audit entry
- Reconciliation executed → `RECONCILIATION_EXECUTED` audit entry
- Missed billing alert → `RECONCILIATION_MISSED_BILLING` audit entry
- All audit entries include provider_id, timestamp, and request ID

## 15.5 Performance Tests

- TTI < 3 seconds on throttled 4G (1.4 Mbps down, 0.7 Mbps up, 270ms RTT)
- Code autocomplete < 200ms with 10,000+ code dataset
- Mobile summary endpoint < 100ms response time

---

# 16. Open Questions

| # | Question | Context |
| --- | --- | --- |
| 1 | What barcode format do AHS wristbands use? | Need to confirm the specific barcode symbology (Code 128, Code 39, QR, etc.) and encoding format for the PHN. Impacts barcode scanner library selection. |
| 2 | Can the Web Barcode Detection API reliably scan wristband barcodes in hospital lighting conditions? | If native API performance is insufficient, a dedicated scanning library (zxing-js) or native camera integration may be needed. |
| 3 | Should encounter logging work offline? | In hospital environments, mobile signal may be intermittent. If offline support is needed, encounters must be queued locally and synced when connectivity returns. |
| 4 | What is the maximum reasonable number of encounters per shift? | Affects UI performance and data model constraints. A busy ED shift might see 40–60 patients. |
| 5 | Should the reconciliation run automatically on import, or require explicit physician trigger? | Automatic is more seamless; explicit gives physician more control. A setting toggle may be appropriate. |
| 6 | How should the system handle a physician with multiple overlapping shifts on the same day? | E.g. a morning clinic shift and an evening ED shift. Reconciliation needs to correctly match encounters to the right shift. |
| 7 | Should partial PHN resolution be allowed to create patient records? | If a last-4 match resolves successfully, should the system auto-create a patient record from the SCC data if the patient doesn't exist in Meritum yet? |
| 8 | Should WCB quick entry be supported on mobile for simple forms (C050E)? | Currently desktop-only. C050E has fewer fields than C050S. Possible simplified mobile WCB entry for basic forms. |
| 9 | When should native apps be built? | Phase 2 timeline depends on user base size and demand for offline/push. Responsive web may be sufficient for 12–18 months. |
| 10 | Should the mobile UI support landscape orientation? | Tablet users may want landscape. Phone users typically portrait. Could support both on tablet breakpoint only. |
| 11 | How should favourites be seeded for new physicians with no claim history and no specialty set? | Current spec: specialty-typical codes from Reference Data. Need specialty-specific seed lists curated. If no specialty set, no seeding occurs. |

---

# 17. Document Control

This domain specifies the mobile-optimised responsive web experience including the Connect Care revision. It shares APIs with the desktop application and adds mobile-specific endpoints for shift management, shift scheduling, encounter logging, favourites, reconciliation, and the mobile summary.

| Item | Value |
| --- | --- |
| Parent documents | Meritum PRD v1.3, MHT-GAP-MVP-001 (Part C), MHT-FRD-MOB-001 (original Domain 10), MHT-FRD-MOB-002 (Connect Care revision) |
| Domain | Mobile Companion (Domain 10 of 13) |
| Build sequence position | Parallel with Domains 8–10 (mobile UI layer on top of existing APIs) |
| Dependencies | Domain 4 (Claim Lifecycle), Domain 5 (Provider Management), Domain 6 (Patient Registry), Domain 2 (Reference Data), Domain 9 (Notifications), Connect Care Integration |
| Version | 2.1 |
| Date | February 2026 |
| Gap analysis items addressed | C1 (revised mobile role), C2 (shift scheduling), C3 (encounter logging), C4 (reconciliation), C5 (CC onboarding) |
| Relationship to MHT-FRD-MOB-002 | This document folds the entire v2 Connect Care revision into the main Domain 10 FRD. The separate MHT-FRD-MOB-002 document is superseded by this unified FRD. |
