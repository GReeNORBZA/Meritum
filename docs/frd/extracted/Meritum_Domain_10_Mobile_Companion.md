# Meritum_Domain_10_Mobile_Companion

MERITUM

Functional Requirements

Mobile Companion

Domain 10 of 13  |  Responsive Web MVP

Meritum Health Technologies Inc.

Version 1.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The Mobile Companion domain specifies the mobile-optimised experience for Meritum. At MVP, this is a responsive web application — not a native iOS/Android app. The goal is to give physicians a usable billing workflow from their phone, particularly for ED shift logging and quick claim entry between patients.

The key insight driving this domain is that most physician billing happens in two contexts: (1) at a desk after clinic hours (desktop), and (2) on the move between patients or during shifts (mobile). The desktop experience (Domains 4–8) is feature-complete. This domain focuses on the subset of workflows that must work well on a phone screen.

## 1.2 Scope

Responsive web design: all Meritum pages render usably on mobile viewports (360px–428px width)

ED shift workflow: start shift → log patients with timestamps → end shift → review and submit

Quick claim entry: patient search → code entry → save as draft

Favourite codes: physician-curated list of frequently used HSC codes for one-tap entry

Notification centre: mobile-optimised notification feed and actions

Dashboard summary: simplified KPI view for mobile

Offline queue (Phase 2): capture claims when offline, sync when connectivity restored

## 1.3 Out of Scope

Native iOS/Android apps (Phase 2; responsive web covers MVP mobile use cases)

Push notifications (Phase 2; requires native apps)

Offline-first architecture (Phase 2; MVP requires connectivity)

Full analytics dashboards on mobile (desktop-only; mobile shows KPI summary)

WCB form entry on mobile (complex multi-section forms are desktop-only; mobile shows read-only WCB claim summary)

Provider profile and settings management (desktop-only)

## 1.4 Design Principles

Thumb-zone optimisation: Primary actions in the bottom half of the screen. Navigation at the bottom.

Minimal input: Favour selection over typing. Code search with autocomplete. Patient selection from recent list.

Speed over completeness: Mobile captures the essentials (patient, code, modifiers, time). Desktop handles review, validation details, and batch management.

No feature parity with desktop: Mobile is a companion, not a replacement. It excels at capture; desktop excels at review and management.

# 2. ED Shift Workflow

The ED shift workflow is the primary mobile use case. Emergency department physicians see 15–40 patients per shift and need to log encounters in real-time. Without Meritum, they typically jot notes on paper or a personal device and transcribe into their billing system later — a process that loses 10–20% of billable encounters.

## 2.1 Shift Lifecycle

## 2.2 Shift Session Data

Shift sessions are stored in the ed_shifts table (Domain 4.0). The Mobile Companion creates and manages these sessions:

Each claim created during a shift has shift_id populated, linking it to the session. This enables shift-level reporting (Domain 8) and batch review by shift.

## 2.3 After-Hours Auto-Detection

When a physician logs a patient encounter during an ED shift, the system automatically detects whether the encounter time qualifies for after-hours billing:

Weekday evening (17:00–23:00): Suggests AFHR modifier if the code is eligible

Weekday night (23:00–08:00): Suggests NGHR modifier if eligible

Weekend/statutory holiday: Suggests WKND modifier if eligible

The auto-detection is a suggestion, not automatic application. The physician confirms during desktop review. On mobile, a subtle indicator shows 'after-hours eligible' on the logged encounter.

# 3. Quick Claim Entry

For clinic-based physicians who want to log a claim between patients without opening a full desktop session.

## 3.1 Quick Entry Flow

**Select patient:** Recent patients list (last 20). Search by PHN or name. Create new patient (first name, last name, PHN, DOB, gender — minimal fields).

**Select code:** Favourites list (one-tap). Search with autocomplete. Recent codes shown.

**Modifiers:** Modifier quick-toggle buttons for the most common modifiers (CMGP, AFHR, NGHR, TM). Full modifier list accessible via 'More'.

**Date of service:** Defaults to today. Selectable calendar picker for prior dates.

**Save:** Saves as draft claim. No validation run on mobile (desktop handles full validation). Confirmation haptic/visual.

## 3.2 Quick Entry Constraints

Quick entry creates AHCIP claims only. WCB claims require too many form fields for mobile entry.

Claims saved from quick entry are in draft state. Full validation and queue/submission happens on desktop.

Diagnostic codes are optional on mobile quick entry. Physician adds them during desktop review.

No batch management on mobile. Mobile is for capture; desktop is for review and submission.

# 4. Favourite Codes

Physicians bill a relatively small set of codes repeatedly. A GP might use 10–20 codes for 80% of their encounters. The favourite codes feature provides one-tap access to these codes on mobile.

## 4.1 Favourites Data Model

Seeding: On first mobile use, system auto-seeds favourites from the physician's 10 most frequently billed codes (if claim history exists). Otherwise, seeded from specialty-typical codes via Reference Data.

## 4.2 Favourites Management

Add/remove favourites from mobile settings or during code search (star icon)

Reorder via drag-and-drop on mobile

Maximum 30 favourites (prevents list from becoming unwieldy)

Default modifiers configurable per favourite (applied automatically on selection, removable)

Favourites sync across mobile and desktop — changes on one appear on the other

# 5. Mobile UI Specifications

## 5.1 Supported Viewports

## 5.2 Mobile Navigation

Bottom tab bar with 4 primary destinations:

Patient search and favourites are accessible from within the Shift and New Claim flows. Full menu (settings, analytics, profile) accessible via hamburger menu or account icon in header.

## 5.3 Mobile Performance Targets

Time to interactive: < 3 seconds on 4G connection

Code search autocomplete: < 200ms response (codes cached on device after first load)

Patient search: < 500ms response

Claim save: < 1 second round-trip

Shift patient logging: < 5 taps from 'Log Patient' to 'Saved' for repeat patient + favourite code

# 6. Offline Queue (Phase 2)

Phase 2 adds offline claim capture for areas with poor connectivity (rural hospitals, remote communities). Architecture accommodations at MVP:

Service worker registration: Registered at MVP to cache static assets and enable fast reload. Not used for offline data at MVP.

Local storage schema: Data model for offline claims defined at MVP (same structure as draft claims). Not populated at MVP.

Sync endpoint: /api/v1/sync/claims endpoint defined at MVP for future offline sync. Returns 501 Not Implemented at MVP.

Phase 2 implementation: claims saved to IndexedDB when offline. Background sync job uploads to server when connectivity restored. Conflict resolution: server wins for claims modified on both client and server. Offline claims clearly marked in UI until synced.

# 7. User Stories & Acceptance Criteria

# 8. API Contracts

Mobile uses the same APIs as desktop (Domains 4–9) with the following mobile-specific additions:

## 8.1 Shift Management

## 8.2 Favourite Codes

## 8.3 Mobile Summary

# 9. Testing Requirements

## 9.1 Responsive Design Tests

All mobile-designated pages render correctly at 360px, 390px, and 428px widths

No horizontal scroll on any mobile page

Touch targets meet minimum 44x44px (WCAG)

Bottom navigation tabs accessible with thumb in any hand position

Text readable without zooming (minimum 16px body text)

## 9.2 ED Shift Tests

Start shift → log 3 patients with favourite codes → end shift → summary shows 3 patients

After-hours detection: shift starting at 18:00 → encounters flagged as after-hours eligible

Active shift persists across page reload and app switch

Only one active shift per physician at a time

Shift claims appear in desktop claim list with shift_id populated

## 9.3 Quick Entry Tests

Complete quick entry in < 30 seconds with recent patient + favourite code

Claim saved as draft, appears in desktop claim list

Patient created from quick entry available in full patient registry

## 9.4 Performance Tests

TTI < 3 seconds on throttled 4G (1.4 Mbps down, 0.7 Mbps up, 270ms RTT)

Code autocomplete < 200ms with 10,000+ code dataset

Mobile summary endpoint < 100ms response time

# 10. Open Questions

# 11. Document Control

This domain specifies the mobile-optimised responsive web experience. It shares APIs with the desktop application and adds mobile-specific endpoints for shift management, favourites, and the mobile summary.

| # | Step | Description |
| --- | --- | --- |
| 1 | Start Shift | Physician taps 'Start Shift'. Selects practice location (pre-filled from default). Records shift_start timestamp. ED shift session created. |
| 2 | Log Patient | For each patient encounter: select patient (search by PHN or name, or create new from minimal fields). System records encounter_start timestamp automatically. |
| 3 | Add Code(s) | Select HSC code from favourites or search. Add modifiers. System pre-fills based on time of day (after-hours auto-detection) and code defaults. |
| 4 | Quick Notes | Optional free-text note for the encounter (e.g., 'laceration repair, 45 min'). Not transmitted in claim — for physician's review reference only. |
| 5 | Next Patient | Save and move to next patient. Encounter saved as draft claim linked to the shift. Minimal taps to log the next encounter. |
| 6 | End Shift | Physician taps 'End Shift'. Records shift_end timestamp. Shows shift summary: patient count, estimated total value, any flagged items. |
| 7 | Review (Desktop) | Physician reviews shift claims on desktop at their convenience. Full validation, modifier review, AI Coach suggestions. Queue for submission. |

| Field | Type | Description |
| --- | --- | --- |
| shift_id | UUID | Primary key |
| provider_id | UUID FK | FK to providers |
| location_id | UUID FK | FK to practice_locations. The ED facility. |
| shift_start | TIMESTAMPTZ | When the shift started |
| shift_end | TIMESTAMPTZ | When the shift ended (null while active) |
| patient_count | INTEGER | Number of patients logged during this shift |
| estimated_value | DECIMAL(10,2) | Sum of expected fees for all claims in this shift |
| status | VARCHAR(20) | ACTIVE, ENDED, REVIEWED. REVIEWED when physician has reviewed all claims on desktop. |
| created_at | TIMESTAMPTZ |  |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| favourite_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers |
| health_service_code | VARCHAR(10) | No | HSC code |
| display_name | VARCHAR(100) | Yes | Physician's custom label (e.g., 'Standard office visit' instead of '03.04A'). Null = use official description. |
| sort_order | INTEGER | No | Display order in favourites list. Physician can reorder. |
| default_modifiers | JSONB | Yes | Array of modifiers to auto-select when this favourite is used. E.g., ['CMGP'] for complex visit code. |
| created_at | TIMESTAMPTZ | No |  |

| Breakpoint | Viewport Width | Target Devices |
| --- | --- | --- |
| Mobile | 360px – 428px | iPhone SE through iPhone 16 Pro Max, Samsung Galaxy S series, Pixel |
| Tablet | 429px – 1024px | iPad Mini, iPad, Samsung Tab. Hybrid layout. |
| Desktop | 1025px+ | Full desktop experience. Not this domain's concern. |

| Tab | Icon | Destination |
| --- | --- | --- |
| Home | Dashboard icon | Mobile KPI summary: today's claims logged, pending queue count, unread notifications count. |
| Shift | Clock icon | ED shift workflow. Shows 'Start Shift' button or active shift status. |
| New Claim | Plus icon | Quick claim entry flow. |
| Notifications | Bell icon | Mobile notification feed with unread badge. |

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| MOB-001 | As an ED physician, I want to start a shift on my phone so I can log patients in real-time | Tap 'Start Shift'. Select location. Shift session created. Timestamp recorded. Shift status visible. |
| MOB-002 | As an ED physician, I want to log a patient encounter during my shift | Select patient (recent or search). Select code (favourite or search). Auto-detect after-hours. Save. < 5 taps for repeat patient + favourite code. |
| MOB-003 | As an ED physician, I want to end my shift and see a summary | Tap 'End Shift'. Summary shows: patient count, estimated value, flagged items. Claims available for desktop review. |
| MOB-004 | As a clinic physician, I want to enter a quick claim between patients | Quick entry: patient → code → save as draft. Under 30 seconds. Works on phone screen. |
| MOB-005 | As a physician, I want one-tap access to my frequently used codes | Favourites list on code selection screen. One tap selects code and auto-applies default modifiers. |
| MOB-006 | As a physician, I want to manage my favourite codes | Add from code search (star icon). Remove from favourites list. Reorder via drag. Max 30. |
| MOB-007 | As a physician, I want to see my key metrics on my phone | Mobile home shows: today's claims, pending queue count, unread notifications. No full dashboard. |
| MOB-008 | As a physician, I want my phone billing experience to be fast | TTI < 3 seconds. Code search < 200ms. Claim save < 1 second. |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/shifts | Start a new shift. Body: location_id. Returns shift_id. |
| GET | /api/v1/shifts/active | Get the active shift (if any). Returns null if no active shift. |
| POST | /api/v1/shifts/{id}/end | End the active shift. Returns shift summary. |
| GET | /api/v1/shifts/{id}/summary | Get shift summary: patient count, estimated value, claim list. |
| GET | /api/v1/shifts | List recent shifts. Params: limit, status filter. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/favourites | Get physician's favourite codes in sort order. |
| POST | /api/v1/favourites | Add a favourite. Body: hsc_code, display_name, default_modifiers, sort_order. |
| PUT | /api/v1/favourites/{id} | Update favourite (display_name, default_modifiers, sort_order). |
| DELETE | /api/v1/favourites/{id} | Remove favourite. |
| PUT | /api/v1/favourites/reorder | Bulk reorder. Body: [{favourite_id, sort_order}]. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/mobile/summary | Lightweight KPI payload: today_claims_count, pending_queue_count, unread_notifications_count, active_shift_id (if any). Single call for mobile home screen. |

| # | Question | Context |
| --- | --- | --- |
| 1 | Should WCB quick entry be supported on mobile for simple forms (C050E)? | Currently desktop-only. C050E has fewer fields than C050S. Possible simplified mobile WCB entry for basic forms. |
| 2 | When should native apps be built? | Phase 2 timeline depends on user base size and demand for offline/push. Responsive web may be sufficient for 12–18 months. |
| 3 | Should the mobile UI support landscape orientation? | Tablet users may want landscape. Phone users typically portrait. Could support both on tablet breakpoint only. |
| 4 | How should favourites be seeded for new physicians with no claim history? | Current spec: specialty-typical codes from Reference Data. Need specialty-specific seed lists curated. |

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | Mobile Companion (Domain 10 of 13) |
| Build sequence position | Parallel with Domains 8–10 (mobile UI layer on top of existing APIs) |
| Dependencies | Domain 4 (Claim Lifecycle), Domain 5 (Provider Management), Domain 6 (Patient Registry), Domain 9 (Notifications) |
| Version | 1.0 |
| Date | February 2026 |

