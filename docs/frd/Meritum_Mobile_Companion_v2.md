# [MERITUM] Functional Requirements — Mobile Companion v2 (Connect Care)

**Document ID:** MHT-FRD-MOB-002
**Domain 10 of 13 (Revision)** | Version 2.0 | 25 February 2026
**Parent Documents:** MHT-GAP-MVP-001 (Part C), MHT-FRD-MOB-001 (original Domain 10)
**Classification:** Internal / Confidential

---

## 1. Domain Overview

### 1.1 Purpose

This FRD revises the Mobile Companion (Domain 10) for physicians who use Connect Care for clinical documentation. When Connect Care integration is active, the SCC extract provides all billing data (service codes, modifiers, diagnostic codes, patient details, facility, BA). The one critical gap in SCC data is **clock time of service** — the extract contains only the encounter date, not the time.

The mobile app's primary role for Connect Care physicians shifts from **billing data capture** to **shift timing context**. This FRD specifies the shift scheduling, PHN-based encounter logging, and Connect Care import reconciliation features that bridge the mobile timing data with SCC import data.

**The original Domain 10 FRD (MHT-FRD-MOB-001) remains valid for non-Connect Care users.** This document supplements it for the Connect Care user path.

### 1.2 Scope

- Revised mobile app role definition for Connect Care vs non-Connect Care users — **addresses gap C1**
- Shift scheduling with iCal RRULE recurrence, reminders, and forgotten-shift handling — **addresses gap C2**
- PHN-based encounter logging (4 capture methods) — **addresses gap C3**
- Connect Care import reconciliation (PHN-based matching, 4 categories, partial PHN resolution) — **addresses gap C4**
- Connect Care user onboarding and mode switching — **addresses gap C5**

### 1.3 Out of Scope

- Quick claim entry (non-Connect Care feature — covered by MHT-FRD-MOB-001)
- Mobile patient creation (non-Connect Care feature)
- Favourite codes CRUD (existing, unchanged)
- Desktop claim form (Domain 4.0)
- SCC parser and import workflow (MHT-FRD-CC-001)
- Intelligence Engine rules (MHT-FRD-MVPADD-001)

### 1.4 Domain Dependencies

| Domain | Direction | Interface |
|--------|-----------|-----------|
| Domain 4.0: Claim Lifecycle Core | Produces → | Claims created from reconciliation receive shift timestamps and modifier annotations |
| Domain 5: Provider Management | Consumed | Provider profile, BA assignments, facility locations, Connect Care flag |
| Domain 6: Patient Registry | Consumed | Patient PHN lookup for encounter matching |
| Domain 7: Intelligence Engine | Produces → | Tier A deterministic signals from shift data (bedside-contingent rules per MHT-FRD-MVPADD-001 B4a) |
| Domain 9: Notification Service | Produces → | Shift reminder events, missed billing alerts, reconciliation prompts |
| MHT-FRD-CC-001 | Consumed by | SCC import rows consumed during reconciliation matching |
| Domain 11: Onboarding | Consumed by | Connect Care flag set during onboarding |

---

## 2. Revised Mobile App Role

**Addresses gap C1.**

### 2.1 Feature Availability by User Context

| Feature | Connect Care User | Non-Connect Care User |
|---------|-------------------|----------------------|
| **Shift scheduling** (C2) | PRIMARY — drives reminders, auto-context, timestamp inference | USEFUL — drives reminders |
| **Shift encounter logging** (PHN scan + timestamp) (C3) | PRIMARY — fills the SCC time gap, enables reconciliation | PRIMARY — timestamps for billing |
| **Quick claim entry** | NOT USED — SCC provides billing data | PRIMARY — manual billing capture |
| **Favourite codes** | NOT USED during shift — used for non-CC clinic days | PRIMARY |
| **Mobile patient creation** | NOT USED — patients come from SCC extract | USEFUL for new patients |
| **Recent patients** | USEFUL for reconciliation reference | PRIMARY |
| **Connect Care reconciliation** (C4) | PRIMARY | N/A |

### 2.2 Mode Switching

The mobile app detects the user's Connect Care status from their provider profile (`providers.is_connect_care_user`). Based on this flag:

- **Connect Care mode:** default view is shift-focused (upcoming shifts, active shift, recent reconciliation). Quick claim entry is accessible via a secondary menu item ("Non-CC Billing") for clinic days when Connect Care is not used.
- **Standard mode:** default view is claim-entry-focused (current behaviour per MHT-FRD-MOB-001). Shift scheduling still available but not the default.

Transition between modes is seamless. Existing favourite codes and templates remain available in both modes.

---

## 3. Shift Scheduling

**Addresses gap C2.**

### 3.1 Shift Schedule Entry

#### 3.1.1 Functional Requirements

- The physician can enter a recurring or one-off shift schedule via a calendar interface (mobile or desktop).
- Each scheduled shift captures: date, start time, end time, facility/location, BA for this shift.
- **Bulk entry:** repeating-pattern builder using iCal RRULE format. Example: "Every Tuesday and Thursday 18:00–02:00 at Foothills ED for March–May." A text/CSV paste is a stretch goal for v2.1.
- Shifts are editable and deletable. Changes to future shifts do not affect past shift logs.
- The schedule is visible as a calendar view on both mobile and desktop, showing upcoming shifts with facility and BA labels.
- When `end_time < start_time` (e.g. 18:00–02:00), the system interprets end_time as the next calendar day.

#### 3.1.2 iCal RRULE Recurrence

The `recurrence_rule` column stores an iCal RRULE string per RFC 5545. Examples:

| Pattern | RRULE |
|---------|-------|
| Every Tuesday and Thursday | `FREQ=WEEKLY;BYDAY=TU,TH` |
| Every weekday | `FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR` |
| Every other Monday | `FREQ=WEEKLY;INTERVAL=2;BYDAY=MO` |
| First and third Saturday of month | `FREQ=MONTHLY;BYDAY=1SA,3SA` |

The backend expands RRULE into concrete shift instances for a rolling 90-day window. Instances are materialised in the `ed_shifts` table when they enter the active window, or when the physician starts the shift manually.

### 3.2 Shift Reminders

#### 3.2.1 Functional Requirements

- The system sends an **in-app push notification** and optionally an **email reminder** before each scheduled shift.
- Default reminder: **30 minutes** before shift start. Configurable per physician: 15 min, 30 min, 1 hour, 2 hours.
- Reminder content: "Your ED shift at {Facility} starts at {time}. Tap to start shift logging."
- Tapping the reminder opens the mobile app directly to the "Start Shift" screen with facility and BA pre-populated from the schedule.
- **Follow-up reminder:** if the physician does not start a shift within 15 minutes of scheduled start, a second notification fires: "Your shift at {Facility} started 15 minutes ago. Start logging to capture encounter timestamps."

#### 3.2.2 Notification Events

| Event Type | Trigger | Priority |
|------------|---------|----------|
| `SHIFT_REMINDER` | `reminder_minutes_before` before scheduled start | HIGH |
| `SHIFT_FOLLOWUP_REMINDER` | 15 min after scheduled start, if shift not started | HIGH |
| `SHIFT_INFERRED_PROMPT` | Import reconciliation finds inferred shift matches | MEDIUM |

### 3.3 Forgotten Shift Handling

When a physician has a scheduled shift but never taps "Start Shift":

1. The system creates an **implicit shift record** based on the schedule:
   - `start_time` = scheduled start
   - `end_time` = scheduled end
   - `facility_id` = scheduled facility
   - `ba_id` = scheduled BA
   - `shift_source` = `'INFERRED'`
   - `inferred_confirmed` = `NULL` (pending physician confirmation)

2. When the Connect Care import arrives and contains claims with encounter dates matching the implicit shift's date AND the facility code matches: the claims are linked to the implicit shift.

3. The physician sees a reconciliation prompt: "You had a scheduled shift at {Facility} on {date} but didn't start shift logging. {N} claims from Connect Care match this shift. Apply shift times for after-hours modifier calculation?"

4. **If confirmed:** the system applies the scheduled shift window as the time-of-service range. All encounters within this window are eligible for AFHR/NGHT based on scheduled times. `inferred_confirmed` = `true`.

5. **If the physician started late** (e.g. tapped "Start Shift" at 19:00 for 18:00 scheduled start): the system uses the **earlier** of scheduled start and actual start for the shift boundary. Encounters in the gap are not lost.

---

## 4. PHN-Based Encounter Logging

**Addresses gap C3.**

### 4.1 Context

For Connect Care physicians, the mobile encounter log captures **patient identity + timestamp** only. No service codes, modifiers, or diagnostic codes — the billing data comes from the SCC import. The mobile app's job is to record *who was seen and when*.

### 4.2 Encounter Capture Methods

Four methods in order of preference (lowest friction first):

#### 4.2.1 Method 1: Wristband Barcode Scan (~2 seconds)

Hospital inpatients and ED registrations at AHS facilities receive a wristband with a barcode encoding their ULI (PHN).

- Physician points phone at patient's wristband.
- App decodes the barcode via device camera, extracts the PHN, validates format (9-digit Alberta, or out-of-province format per B8 definitions).
- Records: PHN + current timestamp + active shift ID.
- Confirmation: brief haptic feedback + "Patient logged — {HH:MM}".
- No further input required. Physician moves to next patient.

This mirrors the wristband scanning gesture for medication administration, which physicians are accustomed to in AHS facilities.

**Implementation:** `apps/web/src/components/domain/mobile/BarcodeScanner.tsx` using the Web Barcode Detection API (or `zxing-js` polyfill for browsers without native support).

#### 4.2.2 Method 2: Quick Patient Search (~5 seconds)

For patients already in Meritum's registry (common for repeat patients at rural EDs):

- Physician taps "Log Encounter" and types 2–3 characters of patient last name.
- App shows matching patients from the physician's patient registry (scoped to `provider_id`).
- Physician taps the patient. PHN captured from existing record.
- Records: PHN + current timestamp + active shift ID.

Fallback for situations where wristband scanning is impractical (wristband obscured, outpatient encounters, camera issue).

#### 4.2.3 Method 3: Manual PHN Entry (~10 seconds)

For patients not yet in Meritum's registry and where scanning is unavailable:

- Physician taps "Log Encounter" and enters the PHN manually (numeric keypad).
- App validates format (Luhn check for Alberta, format check for out-of-province).
- Records: PHN + current timestamp + active shift ID.

Least preferred method but necessary for first-visit patients in non-barcode scenarios.

#### 4.2.4 Method 4: Last-4-Digits Shorthand (~5 seconds)

For rapid logging in high-volume ED environments:

- Physician enters only the last 4 digits of the PHN.
- App records the partial identifier + timestamp + shift ID + `phn_is_partial = true`.
- During reconciliation (Section 5), the last-4 match is resolved against full PHNs in the SCC import.
- Within a single shift, a 4-digit suffix is sufficient to disambiguate (the probability of two patients sharing the same last 4 digits in one ED shift is negligible).
- If an ambiguous match occurs (two patients with same last 4 digits in same shift), the reconciliation step prompts the physician to clarify.

### 4.3 Optional Free-Text Tag

Each encounter log entry has an optional `free_text_tag` field (bed number, initials, brief memory aid). This is **not** treated as PHI — it is at the physician's discretion and is excluded from exports and reports.

### 4.4 Non-Connect Care Users

For physicians who do not use Connect Care, the existing behaviour is preserved: encounter logging includes patient selection, service code, modifiers, and timestamp. The PHN-based logging described above is activated only when the physician's profile has `is_connect_care_user = true`.

---

## 5. Connect Care Import Reconciliation

**Addresses gap C4.**

### 5.1 Trigger

When a Connect Care CSV import is processed (per MHT-FRD-CC-001) and the physician has an active, manual, or inferred shift for the same date and facility, the system performs PHN-based matching between the SCC import rows and the shift encounter log.

### 5.2 Matching Logic

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

### 5.3 Match Categories

After matching, each SCC row and each encounter log entry falls into one of four categories:

| Category | SCC Row | Encounter Log | Meaning | Handling |
|----------|---------|---------------|---------|----------|
| **Full match** | Has matching encounter | Has matching SCC row | Timestamp assigned. Modifier inference possible. | Apply `inferred_service_time = encounter.logged_at`. Evaluate time-based modifier rules. |
| **Unmatched SCC row** | No matching encounter | — | Billing code exists but no shift timestamp. Physician didn't log this encounter. | If shift window entirely within one modifier bracket → apply modifier from shift window. If boundary-crossing → prompt physician for approximate time. If no shift → no inference. |
| **Unmatched encounter** | — | No matching SCC row | Physician logged seeing a patient but no billing code in SCC. Potential missed billing. | Surface as **missed billing alert**. Display timestamp and free-text tag. Physician can go back to SCC or create manual claim. |
| **Shift-only** | Encounter date matches shift, no per-encounter log | — | No encounter logging during shift. Fall back to shift window. | If entirely after-hours → apply modifier. If boundary-crossing → prompt or apply conservative modifier. Encourage future logging. |

### 5.4 Handling Detail: Full Match

- Claim receives `inferred_service_time = encounter.logged_at`.
- Time-based modifier rules evaluate against this timestamp:
  - Weekday 17:00–23:00 → AFHR auto-applied (Tier A deterministic, per MHT-FRD-MVPADD-001 B4a)
  - Any day 22:00–07:00 → NGHT auto-applied
  - Weekend/holiday → AFHR auto-applied (already deterministic from date alone, but timestamp confirms)
- Import summary shows: "Timestamp {HH:MM} from shift log → after-hours modifier applied."

### 5.5 Handling Detail: Unmatched SCC Row

1. **If shift window entirely within one modifier bracket** (e.g. 22:00–06:00 = all NGHT): apply modifier based on shift window alone. No per-encounter timestamp needed.
2. **If shift window crosses modifier boundaries** (e.g. 15:00–23:00): prompt physician: "{N} claim(s) could not be matched to an encounter timestamp. Your shift crossed the after-hours boundary at 17:00. Was this encounter before or after 17:00?" Offer quick time picker defaulting to shift midpoint.
3. **If no shift exists at all** (physician didn't schedule or start a shift): no timestamp inference possible. Claim created without time-of-service metadata. Standard Tier C intel rules fire ("Consider after-hours modifier").

### 5.6 Handling Detail: Unmatched Encounter — Missed Billing Alert

This is one of the highest-value features of the reconciliation. Physicians missing even 1–2 encounters per shift at $30–100/encounter adds up to significant lost revenue over a month.

- Surface as a **missed billing alert** in the import summary: "You logged {N} encounter(s) during your shift that have no matching billing code in Connect Care. Did you forget to capture these in SCC?"
- Display timestamp and (if available) free-text tag for each unmatched encounter to aid recall.
- Physician can: (a) go back to Connect Care and add missing SCC entries, then re-import; or (b) create a manual claim directly in Meritum using the encounter timestamp.
- Notification event: `RECONCILIATION_MISSED_BILLING` (HIGH priority).

### 5.7 Handling Detail: Shift-Only

- Physician started (or has inferred) shift but never logged individual encounters.
- All SCC rows matching shift date + facility linked to the shift.
- Time-of-service inferred from shift window:
  - If entirely after-hours → auto-apply appropriate modifier.
  - If boundary-crossing → prompt or apply conservative (lower-value) modifier and flag for review.
- Missed billing detection not possible (no encounter log to compare).
- Import summary encourages future logging: "Logging encounters during your shift enables automatic after-hours modifier application and missed billing detection."

### 5.8 Reconciliation Summary Display

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

### 5.9 Partial PHN Resolution

When an encounter was logged with only the last 4 digits (Method 4 from Section 4.2.4):

1. During matching, find all SCC rows where Patient ULI ends with the logged 4 digits.
2. **Exactly one match:** resolve automatically. Link encounter to claim. Update context for audit.
3. **Zero matches:** partial PHN doesn't correspond to any patient in the import. Surface as unmatched encounter (possible missed billing, or patient billed under different provider).
4. **Multiple matches** (rare — two patients with same last 4 digits in one shift): prompt physician to select the correct patient from matching candidates, displaying patient name and encounter details from SCC extract to aid identification.

---

## 6. Connect Care User Onboarding

**Addresses gap C5.**

### 6.1 Detection

During onboarding (Domain 11) or via provider settings, the physician indicates whether they use Connect Care for clinical documentation.

**Add to `providers` table:**

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| is_connect_care_user | BOOLEAN | No | Whether physician uses Connect Care. Default false. |
| connect_care_enabled_at | TIMESTAMPTZ | Yes | When Connect Care mode was first enabled |

### 6.2 Mode Activation

- If `is_connect_care_user = true`: the system enables the simplified shift clock (Section 4), shows the "Connect Care Import" navigation item, and adjusts the mobile app's default view to shift-focused.
- If the physician later enables Connect Care: the mobile app transitions gracefully. Existing favourite codes and templates remain available for non-CC clinic days.
- If the physician disables Connect Care: mobile app reverts to standard mode.

### 6.3 SCC Export Guidance

- **Help article:** in-app walkthrough explaining how to export "My Billing Codes" and "My WCB Codes" from Connect Care. Linked from the import page and the help centre (Domain 13).
- **Phase 2 (sFTP) guidance:** instructions on submitting the AHS Service Code Capture Request Form to nominate Meritum as their billing software vendor.

---

## 7. Data Model

### 7.1 New Tables

#### `shift_schedules`

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| schedule_id | UUID | No | Primary key |
| provider_id | UUID FK | No | Physician who owns this schedule |
| facility_id | UUID FK | No | Linked practice location |
| ba_id | UUID FK | No | Business arrangement for this shift |
| start_time | TIME | No | Shift start time (e.g. 18:00) |
| end_time | TIME | No | Shift end time (e.g. 02:00, interpreted as next day if < start) |
| recurrence_rule | TEXT | Yes | iCal RRULE format for recurring shifts. NULL for one-off. |
| effective_from | DATE | No | First date this schedule applies |
| effective_until | DATE | Yes | Last date. NULL = indefinite. |
| reminder_minutes_before | INTEGER | No | Reminder lead time. Default 30. |
| is_active | BOOLEAN | No | Soft delete. Default true. |
| created_at | TIMESTAMPTZ | No | Default now() |
| updated_at | TIMESTAMPTZ | No | Default now() |

**Indexes:** `provider_id`, `(provider_id, effective_from, effective_until)`
**Constraints:** `provider_id REFERENCES providers(provider_id)`, `facility_id REFERENCES practice_locations(location_id)`, `ba_id REFERENCES business_arrangements(ba_id)`

#### `ed_shift_encounters` (Revised)

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| encounter_id | UUID | No | Primary key |
| shift_id | UUID FK | No | Parent shift |
| provider_id | UUID FK | No | Physician (redundant with shift, but enforces scoping at query level) |
| patient_phn | TEXT | No | Full PHN (encrypted at rest) or last-4 shorthand |
| phn_capture_method | VARCHAR(20) | No | BARCODE_SCAN, PATIENT_SEARCH, MANUAL_ENTRY, LAST_4 |
| phn_is_partial | BOOLEAN | No | True if only last 4 digits captured. Default false. |
| logged_at | TIMESTAMPTZ | No | Encounter timestamp (when physician scanned/entered) |
| matched_claim_id | UUID FK | Yes | Populated during reconciliation. FK to claims. |
| free_text_tag | VARCHAR(100) | Yes | Optional memory aid (bed number, initials). NOT PHI. Excluded from exports. |
| created_at | TIMESTAMPTZ | No | Default now() |

**Indexes:** `shift_id`, `provider_id`, `(shift_id, patient_phn)`

### 7.2 Modified Tables

#### `ed_shifts` — New Columns

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| schedule_id | UUID FK | Yes | Linked schedule entry. NULL for ad-hoc shifts. |
| shift_source | VARCHAR(20) | No | MANUAL (physician tapped Start) or INFERRED (created from schedule). Default MANUAL. |
| inferred_confirmed | BOOLEAN | Yes | Physician confirmed the inferred shift. NULL if MANUAL. |

#### `providers` — New Columns

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| is_connect_care_user | BOOLEAN | No | Whether physician uses Connect Care. Default false. |
| connect_care_enabled_at | TIMESTAMPTZ | Yes | When Connect Care mode was first enabled. |

---

## 8. API Contracts

### 8.1 Shift Schedule Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/mobile/schedules` | List shift schedules for authenticated provider. Query: `from`, `to` (date range). |
| POST | `/api/v1/mobile/schedules` | Create a shift schedule (one-off or recurring). |
| PUT | `/api/v1/mobile/schedules/{id}` | Update a shift schedule. |
| DELETE | `/api/v1/mobile/schedules/{id}` | Soft-delete a shift schedule. |
| GET | `/api/v1/mobile/schedules/calendar` | Get materialised shift instances for a date range. Returns concrete dates/times expanded from RRULE. |

**POST `/api/v1/mobile/schedules`** — Request:

```json
{
  "facilityId": "uuid",
  "baId": "uuid",
  "startTime": "18:00",
  "endTime": "02:00",
  "recurrenceRule": "FREQ=WEEKLY;BYDAY=TU,TH",
  "effectiveFrom": "2026-03-01",
  "effectiveUntil": "2026-05-31",
  "reminderMinutesBefore": 30
}
```

### 8.2 Shift Management Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/mobile/shifts/start` | Start a shift. Body: `{ scheduleId?, facilityId, baId }`. Creates ed_shifts record. |
| POST | `/api/v1/mobile/shifts/{id}/end` | End an active shift. |
| GET | `/api/v1/mobile/shifts/active` | Get the currently active shift (if any). |
| GET | `/api/v1/mobile/shifts` | List shifts. Query: `from`, `to`, `status`. |
| GET | `/api/v1/mobile/shifts/{id}` | Get shift details including encounter log. |
| POST | `/api/v1/mobile/shifts/{id}/confirm-inferred` | Confirm an inferred shift. Sets `inferred_confirmed = true`. |

### 8.3 Encounter Logging Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/mobile/shifts/{shiftId}/encounters` | Log an encounter. Body: `{ patientPhn, phnCaptureMethod, phnIsPartial?, freeTextTag? }`. |
| GET | `/api/v1/mobile/shifts/{shiftId}/encounters` | List encounters for a shift. |
| DELETE | `/api/v1/mobile/shifts/{shiftId}/encounters/{id}` | Remove a logged encounter (e.g. accidental scan). |

**POST `/api/v1/mobile/shifts/{shiftId}/encounters`** — Request:

```json
{
  "patientPhn": "123456789",
  "phnCaptureMethod": "BARCODE_SCAN",
  "phnIsPartial": false,
  "freeTextTag": "bed 4"
}
```

Response (201):
```json
{
  "data": {
    "encounterId": "uuid",
    "loggedAt": "2026-02-14T18:32:00.000Z",
    "phnCaptureMethod": "BARCODE_SCAN",
    "confirmation": "Patient logged — 18:32"
  }
}
```

### 8.4 Reconciliation Endpoints

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

---

## 9. Security

### 9.1 Authentication and Authorization

- All mobile/shift endpoints require active authentication and a valid provider session.
- Permission guards:
  - Shift management: `requirePermission('SHIFT_MANAGE')` (new permission key)
  - Encounter logging: `requirePermission('SHIFT_MANAGE')`
  - Reconciliation: `requirePermission('CLAIM_CREATE')`
- Delegates with appropriate permissions may manage shifts and log encounters on behalf of their physician.

### 9.2 Physician Tenant Isolation

- `shift_schedules`, `ed_shifts`, and `ed_shift_encounters` are all scoped to `provider_id` at the repository layer.
- `ed_shift_encounters.provider_id` is redundant with `ed_shifts.provider_id` but is enforced independently to guarantee scoping even if the shift join is bypassed.
- A physician cannot view, modify, or access another physician's shift data, encounter logs, or reconciliation results. Cross-provider access returns 404.

### 9.3 PHI Handling

- **Encounter log contains PHI** (PHN + timestamp). Subject to the same controls as all other PHI:
  - Encrypted at rest (PostgreSQL managed encryption, DO Toronto).
  - PHN masked as `123******` in application logs.
  - Provider-scoped queries only.
- **Free-text tags are NOT treated as PHI** but are excluded from exports and reports as a precaution.
- **No PHI in push notifications or emails.** Shift reminders contain facility and time only, never patient data. Missed billing alerts reference encounter count and timestamps, never PHN.
- **Reconciliation responses mask PHN:** `patientUliMasked: "***456789"` in API responses. Full PHN available only in the linked claim record.

### 9.4 Audit Logging

| Audit Event | Trigger |
|-------------|---------|
| `SHIFT_SCHEDULE_CREATED` | New shift schedule created |
| `SHIFT_SCHEDULE_UPDATED` | Schedule modified |
| `SHIFT_SCHEDULE_DELETED` | Schedule soft-deleted |
| `SHIFT_STARTED` | Physician starts a shift (manual) |
| `SHIFT_ENDED` | Physician ends a shift |
| `SHIFT_INFERRED` | System creates inferred shift from schedule |
| `SHIFT_INFERRED_CONFIRMED` | Physician confirms inferred shift |
| `ENCOUNTER_LOGGED` | Encounter recorded (any capture method) |
| `ENCOUNTER_DELETED` | Encounter removed |
| `RECONCILIATION_EXECUTED` | Reconciliation performed for import batch |
| `RECONCILIATION_CONFIRMED` | Physician confirms reconciliation results |
| `RECONCILIATION_MISSED_BILLING` | Missed billing alert generated |
| `RECONCILIATION_PARTIAL_RESOLVED` | Partial PHN match resolved |
| `RECONCILIATION_TIME_RESOLVED` | Physician provides time for unmatched SCC row |

---

## 10. Testing Requirements

### 10.1 Unit Tests

**Location:** `apps/api/src/domains/mobile/`

**Shift Scheduling:**
- Create one-off shift → stored correctly
- Create recurring shift with RRULE → instances materialised for 90-day window
- RRULE expansion: `FREQ=WEEKLY;BYDAY=TU,TH` → correct dates generated
- End time < start time (e.g. 18:00–02:00) → interpreted as next-day end
- Edit future shift → does not affect past shift logs
- Delete schedule → soft delete, future instances removed

**Shift Reminders:**
- Scheduled shift in 30 min → `SHIFT_REMINDER` event generated
- Shift start time passed + 15 min, no shift started → `SHIFT_FOLLOWUP_REMINDER` generated
- Physician starts shift before reminder → no follow-up fired

**Forgotten Shift:**
- Scheduled shift, no manual start → inferred shift record created with `shift_source = 'INFERRED'`
- Inferred shift confirmed → `inferred_confirmed = true`
- Late start (actual 19:00, scheduled 18:00) → shift boundary = min(18:00, 19:00) = 18:00

**Encounter Logging:**
- Barcode scan with valid Alberta PHN → encounter created, `phn_capture_method = 'BARCODE_SCAN'`
- Patient search → encounter created with full PHN from registry
- Manual entry with invalid Luhn → rejected
- Last-4 shorthand → encounter created with `phn_is_partial = true`
- Optional free_text_tag stored correctly
- Encounter without active shift → rejected (must have active shift)

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
- NGHT rule: encounter at 22:15 → NGHT applied

### 10.2 Integration Tests

**Location:** `apps/api/test/integration/mobile/`

- Create schedule → start shift → log 3 encounters → end shift → verify shift record and encounters
- Schedule with RRULE → verify calendar endpoint returns correct instances
- Start shift from reminder (pre-populated facility + BA) → correct shift record
- Upload SCC CSV → reconcile → full matches get timestamps → modifiers applied → claims updated
- Upload SCC CSV with no shift → no reconciliation, standard claim creation
- Inferred shift + SCC import → reconciliation prompt → confirm → timestamps applied
- Missed billing alert → notification generated with HIGH priority

### 10.3 Security Tests

**Location:** `apps/api/test/security/mobile/`

#### Authentication Enforcement (`mobile.authn.security.ts`)
- Every schedule, shift, encounter, and reconciliation endpoint returns 401 without session

#### Authorization (`mobile.authz.security.ts`)
- Delegate without `SHIFT_MANAGE` → 403 on shift start, encounter log
- Delegate with `SHIFT_MANAGE` → 200 on shift start, encounter log
- Delegate without `CLAIM_CREATE` → 403 on reconciliation confirm

#### Tenant Isolation (`mobile.scoping.security.ts`)
- Physician 1's schedules not visible to Physician 2
- Physician 1's shift encounters not visible to Physician 2
- Physician 1's reconciliation results not accessible by Physician 2
- Physician 2 cannot log encounters on Physician 1's shift
- List endpoints return only authenticated provider's data

#### Input Validation (`mobile.input.security.ts`)
- SQL injection in PHN field → blocked by Zod
- Invalid PHN format (non-numeric) → 400
- XSS in free_text_tag → sanitised
- Non-UUID shift/encounter IDs → 400
- Invalid RRULE format → 400
- Future date > 1 year for schedule → rejected
- Negative reminder_minutes_before → 400

#### Data Leakage (`mobile.leakage.security.ts`)
- Encounter errors do not echo full PHN
- Reconciliation responses mask PHN (`***456789`)
- Shift reminder notifications contain no PHI
- 500 errors expose no internal details

#### Audit Trail (`mobile.audit.security.ts`)
- Shift start → `SHIFT_STARTED` audit entry
- Encounter logged → `ENCOUNTER_LOGGED` audit entry with capture method
- Reconciliation executed → `RECONCILIATION_EXECUTED` audit entry
- Missed billing alert → `RECONCILIATION_MISSED_BILLING` audit entry
- All audit entries include provider_id, timestamp, and request ID

---

## 11. Open Questions

| # | Question | Context |
|---|----------|---------|
| 1 | What barcode format do AHS wristbands use? | Need to confirm the specific barcode symbology (Code 128, Code 39, QR, etc.) and encoding format for the PHN. Impacts barcode scanner library selection. |
| 2 | Can the Web Barcode Detection API reliably scan wristband barcodes in hospital lighting conditions? | If native API performance is insufficient, a dedicated scanning library (zxing-js) or native camera integration may be needed. |
| 3 | Should encounter logging work offline? | In hospital environments, mobile signal may be intermittent. If offline support is needed, encounters must be queued locally and synced when connectivity returns. |
| 4 | What is the maximum reasonable number of encounters per shift? | Affects UI performance and data model constraints. A busy ED shift might see 40–60 patients. |
| 5 | Should the reconciliation run automatically on import, or require explicit physician trigger? | Automatic is more seamless; explicit gives physician more control. A setting toggle may be appropriate. |
| 6 | How should the system handle a physician with multiple overlapping shifts on the same day? | E.g. a morning clinic shift and an evening ED shift. Reconciliation needs to correctly match encounters to the right shift. |
| 7 | Should partial PHN resolution be allowed to create patient records? | If a last-4 match resolves successfully, should the system auto-create a patient record from the SCC data if the patient doesn't exist in Meritum yet? |
| 8 | What RRULE complexity should be supported? | iCal RRULE supports very complex patterns. Should Meritum support the full RFC 5545 RRULE spec or a practical subset (WEEKLY, MONTHLY, BYDAY, INTERVAL)? |

---

## 12. Document Control

| Item | Value |
|------|-------|
| Parent documents | MHT-GAP-MVP-001 (Part C), MHT-FRD-MOB-001 (original Domain 10) |
| Domain | Mobile Companion (Domain 10 of 13) — Connect Care Revision |
| Version | 2.0 |
| Date | 25 February 2026 |
| Author | Engineering |
| Status | DRAFT |
| Gap analysis items | C1, C2, C3, C4, C5 |
| Relationship to MHT-FRD-MOB-001 | This document supplements the original Domain 10 FRD for Connect Care users. The original FRD remains valid for non-Connect Care users. |

---

*End of Document*
