# Meritum — IMA Legal Requirements FRD (Gap Analysis)

> Functional requirements derived from the Information Manager Agreement (IMA) v2.0, pursuant to HIA s.66(2). Each requirement maps an IMA clause to system functionality. This document compares each requirement against the **actual codebase** as of Feb 2026 and identifies only the true gaps.

---

## Document Conventions

- **IMA §X.Y** — references a clause in the IMA v2.0
- **IMPLEMENTED** — functionality already exists in the codebase (verified)
- **PARTIAL** — some supporting infrastructure exists but specific IMA obligations are not met
- **GAP** — no implementation exists; must be built
- **Priority: MVP** — required before first custodian onboards
- **Priority: Post-MVP** — can ship after launch but before scale

---

## Requirements Already Satisfied by Existing Code

The following IMA requirements are **already implemented** and require no additional work (or only require verification during security testing):

### A1. Digital IMA Acceptance — IMPLEMENTED

**IMA Reference:** Acceptance clause; §8.1

**What exists:**
- `ima_records` table in `onboarding.schema.ts` with: `templateVersion` (varchar 20), `documentHash` (varchar 64 / SHA-256), `acknowledgedAt` (timestamptz), `ipAddress` (varchar 45), `userAgent` (varchar 500)
- Onboarding step 7 = `IMA_ACKNOWLEDGEMENT` (required step)
- `IMA_TEMPLATE_VERSION = '1.0.0'` constant in `onboarding.constants.ts`
- Audit action: `onboarding.ima_acknowledged`
- Multiple rows per provider supported (re-acknowledgement on version updates)
- Platform blocks PHI access until `onboardingCompleted = true`

**Verdict:** Fully implemented. No gap.

---

### B1. Practice Administrator Role — IMPLEMENTED (schema/constants)

**IMA Reference:** §3.6, §2.3(d)

**What exists:**
- `PRACTICE_ADMIN` role defined in `iam.constants.ts`
- Permission set restricted to exactly 4 permissions: `PRACTICE_SEAT_VIEW`, `PRACTICE_SEAT_MANAGE`, `PRACTICE_INVOICE_VIEW`, `PRACTICE_SETTINGS_EDIT`
- `practices` and `practiceMemberships` tables in `platform.schema.ts`
- `practiceInvitations` table exists
- Auth plugin's `authorize()` checks delegate permissions; practice_admin would be similarly gated

**Verdict:** Schema and constants fully implemented. Middleware enforcement and security tests needed but that's standard domain completion work, not an IMA gap. Practice tier is Post-MVP regardless.

---

### C1. Real-Time Delegate Revocation — IMPLEMENTED

**IMA Reference:** §3.5

**What exists:**
- `delegateRelationships` table with status `INVITED → ACTIVE → REVOKED`, plus `revokedAt`, `revokedBy` fields
- `delegateLinkages` table (IAM layer) with `isActive` boolean
- Delete endpoint: `DELETE /api/v1/delegates/:id`
- Audit action: `delegate.revoked`
- Session revocation mechanism in IAM (sessions table has `revoked` boolean + `revokedReason`)

**Action needed:** Verify during security testing that revoking a delegate immediately invalidates their active sessions for that physician context. This is a test verification, not a code gap.

---

### C2. Delegate Disclosure Boundary — IMPLEMENTED

**IMA Reference:** §2.3(d)

**What exists:**
- 24 granular delegate permissions in `provider.constants.ts`
- 4 permission templates (full, billing entry, review/submit, view-only)
- Auth plugin's `authorize()` pre-handler checks `delegateContext.permissions`
- Comprehensive security test files exist for all domains (`authz.security.ts`)

**Action needed:** Verify completeness during security testing. Not a code gap.

---

### L1. SOMB Version Tracking — IMPLEMENTED

**IMA Reference:** §3.13

**What exists:**
- `referenceDataVersions` table with: `dataSet`, `versionLabel`, `effectiveFrom`, `effectiveTo`, `publishedAt`, `sourceDocument`, `changeSummary`, `recordsAdded`, `recordsModified`, `recordsDeprecated`, `isActive`
- Partial unique constraint: one active version per dataset
- Every reference table (`hscCodes`, `governingRules`, `modifierDefinitions`, etc.) has a `versionId` FK
- Full staging workflow: upload → validate → diff → publish
- Published versions are immutable (corrections require new version)

**Minor enhancement (not a gap):** An admin dashboard widget showing "days since last SOMB update" with a 30-day warning would operationally support the IMA §3.13 commitment, but the underlying version tracking infrastructure is complete.

---

### K4. Security Remediation Notifications — PARTIAL (adequate)

**IMA Reference:** §9.3

**What exists:**
- `MAINTENANCE_SCHEDULED` notification event type
- `statusComponents` table (8 monitored components)
- `statusIncidents` table with severity levels and status progression
- `incidentUpdates` table (append-only timeline)
- Admin workflows: `createIncident()`, `updateIncident()`, `updateComponentStatus()`

**Minor enhancement:** Add a scheduling constraint to avoid Thursday submission window for planned maintenance. This is an operational policy, not a code gap.

---

## True Gaps — New Functionality Required

### GAP 1: IMA Amendment Workflows (A2, A3)

**IMA Reference:** §11.3(a) non-material, §11.3(b) material

**What's missing:** No `ima_amendments` or `ima_amendment_responses` tables. No amendment notification types. No blocking interstitial for acknowledgement. No consent/rejection workflow.

**What's needed:**

**Tables:**
```
ima_amendments
  amendment_id          UUID PK
  amendment_type        ENUM('NON_MATERIAL', 'MATERIAL')
  title                 TEXT
  description           TEXT
  document_hash         TEXT (SHA-256)
  notice_date           TIMESTAMPTZ
  effective_date        TIMESTAMPTZ      -- notice + 30d (non-material) or + 60d (material)
  created_by            UUID FK → users
  created_at            TIMESTAMPTZ

ima_amendment_responses
  response_id           UUID PK
  amendment_id          UUID FK → ima_amendments
  provider_id           UUID FK → providers
  response_type         ENUM('ACKNOWLEDGED', 'ACCEPTED', 'REJECTED')
  responded_at          TIMESTAMPTZ
  ip_address            TEXT
  user_agent            TEXT
```

**Logic:**
- Non-material (§11.3a): After `effective_date`, blocking interstitial until acknowledged. Custodian cannot access PHI until they acknowledge.
- Material (§11.3b): 60-day window. Accept or reject. Non-response = existing terms continue. If Meritum can't operate under old terms, 90-day termination notice → 45-day export.
- Notification events needed: `IMA_AMENDMENT_NOTICE`, `IMA_AMENDMENT_REMINDER`, `IMA_AMENDMENT_DEADLINE`
- Reminders at 30d and 7d before deadline (material)

**Priority:** MVP (non-material); Post-MVP (material — unlikely before first amendment)

---

### GAP 2: Patient Access Request Export (D1)

**IMA Reference:** §3.9

**What's missing:** No per-patient Health Information export feature. The `generatedReports` table supports physician-level reports, but there's no "export all HI for patient X" capability.

**What's needed:**
- Endpoint: `POST /api/v1/patients/:id/export` (physician-authenticated)
- Compiles all HI for a specific patient scoped to the requesting custodian:
  - Patient demographics
  - All claims (all states) linked to that patient
  - All assessments/rejections linked to those claims
  - All WCB form data for that patient
  - Audit log entries referencing that patient
- Output: ZIP with CSV files + manifest
- Download via presigned URL (time-limited, authenticated, physician-scoped)
- Audit action: `patient.access_request_export`
- Tenant-isolated: only exports data where `provider_id` = authenticated physician

**Priority:** MVP (HIA Part 2 obligation from day one)

---

### GAP 3: Patient Correction Audit Trail (D2)

**IMA Reference:** §3.10

**What's missing:** Patient CRUD exists, but standard PATCH operations don't capture `correction_reason`, `old_value`, or `new_value` in a structured way. The audit log captures HTTP request bodies but doesn't produce a purpose-built correction record linking old and new values per field.

**What's needed:**
- When a physician updates patient demographics, the system must record:
  - Each changed field: `field_name`, `old_value`, `new_value`
  - `correction_reason` (required text field, prompted in UI)
  - `corrected_by` (user_id)
  - `correction_type`: `PATIENT_DEMOGRAPHICS` or `CLAIM_ANNOTATION`
- For already-submitted claims: create an annotation record (claims are immutable post-submission), not a modification
- Audit action: `patient.correction_applied`

**Implementation approach:** Extend the existing patient PATCH handler to:
1. Accept an optional `correction_reason` field
2. Compute a diff of changed fields before applying the update
3. Write a structured audit log entry with old/new values
4. When `correction_reason` is present, use audit action `patient.correction_applied` instead of generic `patient.updated`

This is a handler-level change + audit log enhancement, not a new table.

**Priority:** MVP (HIA s.13 obligation from day one)

---

### GAP 4: Export Window Duration Mismatch (E2)

**IMA Reference:** §8.3

**What exists:** `DELETION_GRACE_PERIOD_DAYS = 30` in `platform.constants.ts`. Deletion is scheduled 30 days after CANCELLED.

**What the IMA requires:** 45-day export access window after subscription ends.

**What's needed:**
- Change `DELETION_GRACE_PERIOD_DAYS` from `30` to `45`
- Add a notification sequence during the export window:
  - Day 0: "Your 45-day export window has started"
  - Day 30: reminder
  - Day 38: urgent reminder
  - Day 44: final warning
  - Day 45: "Export window closed. Data destruction will begin."
- Notification events needed: `EXPORT_WINDOW_STARTED`, `EXPORT_WINDOW_REMINDER`, `EXPORT_WINDOW_CLOSING`, `EXPORT_WINDOW_CLOSED`

**Priority:** MVP (contractual obligation)

---

### GAP 5: Data Destruction Completeness (F1)

**IMA Reference:** §8.4

**What exists:** `runDeletionCheck()` in `platform.service.ts` deletes claims, patients, reports, strips PII from audit logs, anonymises AI data, deactivates user account.

**What's missing:**
1. **File storage cleanup:** No mention of deleting files from DO Spaces (uploaded documents, generated reports) scoped to the provider
2. **Backup purge tracking:** IMA requires removal from backups within 90 days. No tracking mechanism.
3. **Written confirmation of destruction:** IMA requires written confirmation within 10 business days of complete deletion. No confirmation email is sent.

**What's needed:**
- Add DO Spaces file deletion to the deletion pipeline (delete all objects with provider_id prefix)
- Add tracking fields to subscriptions or a new table:
  ```
  data_destruction_tracking
    tracking_id           UUID PK
    provider_id           UUID FK
    active_deleted_at     TIMESTAMPTZ NULL
    files_deleted_at      TIMESTAMPTZ NULL
    backup_purge_deadline TIMESTAMPTZ NULL   -- active_deleted_at + 90 days
    backup_purged_at      TIMESTAMPTZ NULL
    confirmation_sent_at  TIMESTAMPTZ NULL
  ```
- Automated email: "Your data has been permanently deleted from all Meritum systems" — sent within 10 business days of `backup_purged_at`
- Admin dashboard: list of pending backup purge deadlines
- Notification event: `DATA_DESTRUCTION_CONFIRMED`

**Priority:** MVP

---

### GAP 6: Breach Notification System (H1, H2)

**IMA Reference:** §6.1–6.7

**What's missing:** No breach-related tables, no breach notification event types, no breach management workflow, no evidence preservation mechanism. Zero implementation.

**What's needed:**

**Tables:**
```
breach_records
  breach_id               UUID PK
  breach_description      TEXT
  breach_date             TIMESTAMPTZ
  awareness_date          TIMESTAMPTZ         -- starts 72h clock
  hi_description          TEXT
  includes_iihi           BOOLEAN
  affected_count          INTEGER NULL
  risk_assessment         TEXT
  mitigation_steps        TEXT
  contact_name            TEXT
  contact_email           TEXT
  status                  ENUM('INVESTIGATING','NOTIFYING','MONITORING','RESOLVED')
  evidence_hold_until     TIMESTAMPTZ NULL    -- MIN awareness_date + 12 months
  created_by              UUID FK → users
  created_at              TIMESTAMPTZ
  resolved_at             TIMESTAMPTZ NULL

breach_affected_custodians
  id                      UUID PK
  breach_id               UUID FK → breach_records
  provider_id             UUID FK → providers
  initial_notified_at     TIMESTAMPTZ NULL
  notification_method     TEXT NULL

breach_updates
  update_id               UUID PK
  breach_id               UUID FK → breach_records
  update_type             ENUM('INITIAL','SUPPLEMENTARY')
  content                 TEXT
  sent_at                 TIMESTAMPTZ
  created_by              UUID FK → users
```

**Logic:**
- Admin creates breach record → system identifies affected custodians
- 72-hour notification deadline tracked from `awareness_date`
- Notifications sent to BOTH primary and secondary email (see GAP 7)
- Supplementary updates as new information becomes available
- Evidence preservation: set `evidence_hold_until` = MAX(resolved_at + 12 months, ...) and prevent any log cleanup touching that period
- Notification events: `BREACH_INITIAL_NOTIFICATION`, `BREACH_UPDATE`

**Priority:** MVP (regulatory obligation from day one)

---

### GAP 7: Secondary Contact Email (K1)

**IMA Reference:** §11.7

**What's missing:** No `secondary_email` field anywhere in the codebase. Notification system only sends to a single `recipientEmail`.

**What's needed:**
- Add `secondaryEmail` (varchar 100, nullable) to the `users` table or `providers` table
- Zod validation: valid email, cannot equal primary email
- Update account settings endpoint to allow setting/clearing secondary email
- Update notification service: for breach notifications (GAP 6) and material IMA amendment notices (GAP 1), send to BOTH primary and secondary email
- Audit action: `account.secondary_email_updated`

**Priority:** MVP (IMA §11.7 requires this for breach and amendment notices)

---

### GAP 8: Sub-Processor Change Notices (I1)

**IMA Reference:** §5.3

**What's missing:** No tables, no notification types, no objection/acceptance workflow.

**What's needed:**

**Tables:**
```
sub_processor_notices
  notice_id               UUID PK
  sub_processor_name      TEXT
  processing_description  TEXT
  data_location           TEXT
  notice_date             TIMESTAMPTZ
  objection_deadline      TIMESTAMPTZ         -- notice_date + 30 days
  created_by              UUID FK → users
  created_at              TIMESTAMPTZ

sub_processor_responses
  response_id             UUID PK
  notice_id               UUID FK → sub_processor_notices
  provider_id             UUID FK → providers
  response_type           ENUM('ACCEPTED','OBJECTED','DEEMED_ACCEPTED')
  responded_at            TIMESTAMPTZ NULL
```

**Logic:**
- Admin creates notice → notification to all active custodians
- 30-day objection window
- Silence after deadline = `DEEMED_ACCEPTED`
- Objectors offered penalty-free termination with standard data export
- Notification events: `SUB_PROCESSOR_NOTICE`, `SUB_PROCESSOR_DEADLINE_REMINDER`

**Priority:** Post-MVP (unlikely at launch — only DigitalOcean as sub-processor)

---

### GAP 9: PHI Read-Access Audit Logging (N1)

**IMA Reference:** §4.3(d)

**What exists:** The `auditLogPlugin` in `auth.plugin.ts` only logs **state-changing requests** (POST, PUT, PATCH, DELETE). Line 248: `STATE_CHANGING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])`. Line 253: `shouldLog = routeConfig.auditLog ?? STATE_CHANGING_METHODS.has(request.method)`.

**What the IMA requires:** "audit logging of access to **and actions performed on** Health Information." This includes GET requests that return PHI.

**What's needed:**
- Extend the audit logging to cover GET requests on PHI endpoints
- Not ALL GETs (static assets, health checks, etc.) — only endpoints that return Health Information:
  - `GET /api/v1/patients/*`
  - `GET /api/v1/claims/*`
  - `GET /api/v1/ahcip/*`
  - `GET /api/v1/wcb/*`
  - `GET /api/v1/analytics/*` (where PHI is included)
  - `GET /api/v1/providers/*` (where PHI is included)
- Implementation: add `auditLog: true` to the route config for PHI-returning GET endpoints, which overrides the default state-changing-only behaviour (the mechanism already exists at line 253)
- Consider a lighter-weight access log (resource type + ID + user + timestamp) vs. the full audit entry to manage volume

**Priority:** MVP (HIA audit obligation from day one)

---

### GAP 10: Custodian Incapacity/Death Data Hold (G1, G2)

**IMA Reference:** §8.7

**What's missing:** No `DATA_HOLD` account state. No data hold tracking. No representative access mechanism.

**What's needed:**

**Tables:**
```
data_holds
  hold_id                 UUID PK
  provider_id             UUID FK → providers
  hold_reason             ENUM('DEATH','INCAPACITY','ABANDONMENT')
  hold_start              TIMESTAMPTZ
  default_end             TIMESTAMPTZ         -- start + 120 days
  extended_end            TIMESTAMPTZ NULL     -- OIPC direction
  representative_name     TEXT NULL
  representative_email    TEXT NULL
  representative_role     TEXT NULL
  status                  ENUM('ACTIVE','EXPORT_IN_PROGRESS','COMPLETED','EXTENDED')
  created_by              UUID FK → users
  created_at              TIMESTAMPTZ
```

**Logic:**
- Admin-initiated: set account to data hold, disable credentials, disable delegates, suspend billing
- 120-day default hold; extendable by OIPC direction
- Representative can be granted export-only access (time-limited credential)
- After hold expires without extension: trigger data destruction (GAP 5)

**Priority:** Post-MVP (edge case, but must exist before scale)

---

### GAP 11: Complete Health Information Export Package (E1)

**IMA Reference:** §8.3

**What exists:** `generatedReports` table, `DATA_EXPORT` permission (preserved in CANCELLED state), `DATA_EXPORT_READY` notification event. Report infrastructure generates specific report types.

**What's missing:** A **complete Health Information export** that includes ALL data as a portable ZIP/CSV bundle. The existing report system generates specific reports (revenue summary, claim detail, etc.) — it doesn't produce a comprehensive "export everything" package.

**What's needed:**
- New export type: `FULL_DATA_PORTABILITY` in the report system
- Contents (one CSV per entity):
  - patients.csv (all patients, all fields)
  - claims.csv (all claims, all states, all line items)
  - assessments.csv (all assessments and line items)
  - wcb_claims.csv + wcb_form_data.csv
  - pcpcm_enrolments.csv + pcpcm_payments.csv
  - provider_profile.csv (BAs, locations, preferences)
  - delegate_relationships.csv
  - ai_suggestions.csv
  - audit_log.csv (all entries for this provider)
  - manifest.json (schema descriptions, export metadata)
- Generated asynchronously; notification when ready
- Download via presigned URL (time-limited, authenticated, physician-scoped)
- Available at no additional cost
- This is what the 45-day post-termination window (GAP 4) provides access to

**Priority:** MVP

---

## Summary: True Gaps Only

### Already Implemented (no work needed)
| ID | Requirement | Status |
|----|------------|--------|
| A1 | IMA digital acceptance | `ima_records` table, onboarding step 7, SHA-256 hash, IP, UA |
| B1 | Practice admin role | `PRACTICE_ADMIN` role + 4 permissions + practice tables |
| C1 | Delegate revocation | Revoke endpoint + session revocation mechanism |
| C2 | Delegate disclosure boundary | 24 permissions + auth plugin enforcement |
| L1 | SOMB version tracking | `referenceDataVersions` + staging workflow |
| K4 | Security remediation notifications | Status page + incidents + `MAINTENANCE_SCHEDULED` |

### True Gaps (work required)

**MVP (11 items):**

| # | Gap | IMA § | Complexity | Key Work |
|---|-----|-------|-----------|----------|
| 1 | IMA amendment workflows | §11.3 | Medium | 2 new tables, blocking interstitial, 3 notification types |
| 2 | Patient access request export | §3.9 | Medium | New endpoint, cross-table patient HI compilation |
| 3 | Patient correction audit trail | §3.10 | Low | Extend PATCH handler, structured diff logging |
| 4 | Export window 30→45 days | §8.3 | Low | Change constant, add 4 notification types |
| 5 | Data destruction completeness | §8.4 | Medium | DO Spaces cleanup, backup tracking, confirmation email |
| 6 | Breach notification system | §6.1–6.7 | High | 3 new tables, admin workflow, 72h deadline, evidence hold |
| 7 | Secondary contact email | §11.7 | Low | 1 field, validation, dual-delivery for breach/amendment |
| 8 | PHI read-access audit logging | §4.3(d) | Low | Add `auditLog: true` to PHI GET route configs |
| 9 | Complete HI export package | §8.3 | High | New export type, cross-table compilation, ZIP generation |
| 10 | Export window notifications | §8.3 | Low | 4 notification events for the 45-day window |
| 11 | Destruction confirmation email | §8.4 | Low | Automated email after backup purge |

**Post-MVP (3 items):**

| # | Gap | IMA § | Complexity | Key Work |
|---|-----|-------|-----------|----------|
| 12 | Sub-processor change notices | §5.3 | Medium | 2 new tables, objection workflow |
| 13 | Data hold (incapacity/death) | §8.7 | Medium | New table, admin workflow, representative access |
| 14 | De-identification pipeline | §2.4 | High | k-anonymity (k=5), batch de-ID job |

### Removed from Original FRD (not gaps)
| Original ID | Reason Removed |
|-------------|---------------|
| A1 | `ima_records` table fully implements this |
| B1 | `PRACTICE_ADMIN` role + permissions already defined |
| C1, C2 | Delegate system fully built; needs test verification only |
| L1 | `referenceDataVersions` fully implements version tracking |
| K2, K3 | Change of control / cessation notifications are admin-initiated emails, not system features. Can be sent through existing notification infrastructure when needed. |
| J1 | Existing `SUSPENDED` subscription state + `account.suspended` audit action already covers security-driven restriction. The existing state preserves DATA_EXPORT access. |
| M1 | De-identification pipeline remains a gap but is clearly Post-MVP |
| A3 | Merged into GAP 1 (both amendment types handled together) |
