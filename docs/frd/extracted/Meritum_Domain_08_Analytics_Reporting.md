# Meritum_Domain_08_Analytics_Reporting

MERITUM

Functional Requirements

Analytics & Reporting

Domain 8 of 13  |  Critical Path: Position 8

Meritum Health Technologies Inc.

Version 2.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The Analytics & Reporting domain provides physicians with visibility into their billing performance. It transforms raw claim data into actionable dashboards, trend analyses, and exportable reports that help physicians understand their revenue, identify rejection patterns, monitor claim aging, and share financial summaries with their accountants.

This domain is read-only — it consumes data from the Claim Lifecycle, Provider Management, Reference Data, and Intelligence Engine but never modifies claim or provider records. It serves as the physician's billing intelligence layer, complementing the AI Coach's per-claim suggestions with aggregate practice-level insights.

## 1.2 Scope

Revenue dashboards: total revenue, revenue by BA, revenue by location, period-over-period comparison

Submission tracking: claims submitted, assessed, paid, rejected, adjusted — counts and values

Rejection analysis: top rejection codes, rejection rate by HSC code, rejection trends, corrective action effectiveness

Claim aging: unresolved claims by age bracket, approaching deadline alerts

AI Coach performance: suggestion acceptance rates, revenue recovered from accepted suggestions

Multi-site breakdown: per-location revenue, claims, and rejection rates for locum/multi-site physicians

WCB analytics: claims by form type, timing tier distribution, fee tier analysis

ARP analytics: total ARP claims, TM units, rejection rate, assessment results; TM summary report per billing period

Reciprocal billing reporting: out-of-province claim volumes, acceptance rates, province-specific rejection patterns

Accountant export: structured financial summaries for tax preparation

Data portability export: complete claim history export per HIA data portability requirements

Scheduled reports: automated weekly/monthly report generation and delivery via subscription model

Analytics caching layer: pre-computed aggregates with nightly batch refresh, event-driven incremental updates, and stale-cache detection

## 1.3 Out of Scope

Claim modification or state changes (Domain 4 Claim Lifecycle)

Real-time claim monitoring (Domain 4; Analytics shows historical/aggregate views)

AI suggestion generation (Domain 7 Intelligence Engine; Analytics shows acceptance metrics)

Cross-physician benchmarking with identified data (privacy constraint; only anonymised specialty cohort comparisons)

## 1.4 Domain Dependencies

| Domain | Direction | Interface |
| --- | --- | --- |
| 1 Identity & Access | Consumed | Authentication, RBAC. Reports scoped to physician. Delegates with ANALYTICS_VIEW, REPORT_VIEW, REPORT_EXPORT, DATA_EXPORT permissions. |
| 2 Reference Data | Consumed | HSC code descriptions, explanatory code descriptions, modifier names for human-readable report labels. |
| 4.0 Claim Lifecycle Core | Consumed | Claim data: states, dates, fees, validation results. The primary data source. Event-driven cache invalidation on claim state changes. |
| 4.1 AHCIP Pathway | Consumed | AHCIP batch history, assessment results, explanatory codes, PCPCM routing data, ARP/shadow billing claims. |
| 4.2 WCB Pathway | Consumed | WCB claim data: form types, timing tiers, fee calculations, return file results. Invoice line amounts. |
| 5 Provider Management | Consumed | BA numbers, practice locations (including functional_centre for location-based joins), RRNP rates, specialty, WCB configuration flag, multi-location detection. |
| 6 Patient Registry | Consumed | Patient demographics for data portability export. Province-of-origin for reciprocal billing reporting. |
| 7 Intelligence Engine | Consumed | Suggestion events (ai_suggestion_events): generated, accepted, dismissed counts and revenue impact for AI Coach metrics. Provider learning (ai_provider_learning): suppressed rules. Rule definitions (ai_rules): rule names. |
| 9 Notification Service | Consumed | Report delivery via in-app notification and email (scheduled reports). Event type dispatching for report-ready notifications. |

# 2. Module Architecture

## 2.1 Structural Deviation

The Analytics & Reporting domain uses a subdirectory-based module structure rather than the standard flat 5-file pattern. This deviation reflects the domain's higher number of specialized components: four repositories, three route files, and five services.

```
domains/analytics/
├── repos/
│   ├── analytics-cache.repo.ts         # Pre-computed metrics CRUD (upsert, bulk, stale detection, cleanup)
│   ├── dashboard-query.repo.ts         # Read-only SQL queries against claim/provider/intelligence tables
│   ├── generated-reports.repo.ts       # Report lifecycle: create, status update, list, download readiness
│   └── report-subscriptions.repo.ts    # Subscription CRUD, due-subscription queries for scheduler
├── routes/
│   ├── dashboard.routes.ts             # 7 GET endpoints for dashboard data (revenue, rejection, aging, WCB, AI Coach, multi-site, KPIs)
│   ├── report.routes.ts                # 5 endpoints for report generation, status, download, listing
│   └── subscription.routes.ts          # 4 endpoints for report subscription CRUD
├── services/
│   ├── cache-refresh.service.ts        # Nightly batch refresh, event-driven incremental, stale detection, cleanup
│   ├── dashboard.service.ts            # Period resolution, cache-or-compute logic, comparison/delta computation
│   ├── download.service.ts             # Secure file streaming, link expiry enforcement, file cleanup
│   ├── report-generation.service.ts    # Accountant CSV/PDF generation, data portability ZIP creation
│   └── scheduled-reports.service.ts    # Cron-driven subscription processing (daily/weekly/monthly/quarterly)
```

All repositories enforce physician scoping on every query that touches PHI. The dashboard query repository operates as read-only against foreign domain tables (claims, ahcip_claim_details, wcb_claim_details, wcb_invoice_lines, practice_locations, ai_suggestion_events, ai_provider_learning, ai_rules) and never performs INSERT/UPDATE/DELETE on those tables.

# 3. Dashboard Specifications

The analytics dashboard is the physician's primary view of their billing performance. It is designed for at-a-glance comprehension with drill-down capability. All dashboard data is scoped to the authenticated physician. Every dashboard endpoint uses the `ANALYTICS_VIEW` permission guard.

## 3.1 Revenue Overview Dashboard

The default landing view. Shows aggregate financial performance.

| Widget | Specification |
| --- | --- |
| Total Revenue (KPI card) | Sum of assessed_fee for paid AHCIP claims in the selected period. Joined from ahcip_claim_details. Compared to prior period (delta shown as $ and %). Green/red indicator. |
| Claims Submitted (KPI card) | Count of claims entering submitted/assessed/paid/rejected/adjusted state in the period. Prior period comparison. |
| Rejection Rate (KPI card) | rejected / (assessed + rejected + adjusted) as percentage. Prior period comparison. Red if > 10%. |
| Average Fee Per Claim (KPI card) | Total revenue / paid claim count. Prior period comparison. |
| Revenue Trend (line chart) | Monthly revenue over selected period grouped by YYYY-MM. Separate AHCIP and WCB lines when claim_type filter is BOTH. |
| Revenue by BA (bar chart) | For PCPCM dual-BA physicians: side-by-side PCPCM BA vs FFS BA revenue. Single-BA physicians see total only. Grouped by acd.ba_number. |
| Top 10 HSC Codes (table) | Most frequently billed HSC codes with count, total revenue, and rejection rate per code. Limited to top 10 by assessed_fee sum descending. |
| Pending Pipeline (KPI card) | Total value of claims in QUEUED + SUBMITTED states (submitted_fee). Represents expected future revenue. |

## 3.2 Rejection Analysis Dashboard

| Widget | Specification |
| --- | --- |
| Rejection Rate Trend (line chart) | Monthly rejection rate over selected period. Target line at 5% (industry benchmark). |
| Top Rejection Codes (bar chart) | Top explanatory codes (AHCIP) extracted from assessment_explanatory_codes JSONB via LATERAL jsonb_array_elements_text. Each bar shows count. |
| Rejection by HSC Code (table) | HSC codes with highest rejection counts. Columns: HSC code, total claims decided, rejected count, rejection %, computed per-row. HAVING filter excludes HSC codes with zero rejections. |
| Rejection Resolution (funnel) | Rejected → Resubmitted → Paid on Resubmission → Written Off. Resubmission tracking requires audit trail cross-reference (currently approximated from current state counts). |
| Corrective Action Effectiveness | For claims resubmitted after rejection: success rate on second submission. Broken down by rejection code. |
| Rejection Heatmap | Calendar heatmap showing rejection count by day/week. Highlights submission weeks with high rejection rates. |

## 3.3 Claim Aging Dashboard

The aging dashboard is always real-time (point-in-time snapshot, no period parameter). It uses the current date to compute age brackets.

| Widget | Specification |
| --- | --- |
| Aging Brackets (stacked bar) | Unresolved claims (DRAFT, VALIDATED, QUEUED, SUBMITTED) grouped: 0–30 days, 31–60 days, 61–90 days, 90+ days from DOS. Count and value per bracket. Values computed from submitted_fee via LEFT JOIN to ahcip_claim_details. |
| Approaching Deadline (table) | Claims within 7 days of submission_deadline. Sorted by urgency (days_remaining ascending). Direct link to claim for action. |
| Expired Claims (KPI card) | Claims in EXPIRED state. Count only (no period filter). |
| Average Resolution Time (KPI card) | Mean days from date_of_service to updated_at for PAID claims. Approximation using updated_at as terminal state timestamp. |
| Stale Claims (table) | Claims in DRAFT or VALIDATED state created more than 14 days ago. May represent forgotten or incomplete billing. |

## 3.4 WCB Analytics Dashboard

Visible only to physicians with WCB configuration (checked via `hasWcbConfig(providerId)` dependency). Returns 404 if the physician has no WCB setup.

| Widget | Specification |
| --- | --- |
| WCB Claims by Form Type (donut chart) | Distribution of WCB claims across form types (form_id from wcb_claim_details). Count and revenue per form type. Revenue computed via LATERAL subquery summing wcb_invoice_lines.amount. |
| Timing Tier Distribution (stacked bar) | Claims by timing tier extracted from claims.validation_result->>'timing_tier' JSONB path. Shows count per tier. |
| Fee Tier Analysis (table) | Total fee and average fee per timing tier. Revenue from wcb_invoice_lines. Highlights claims where earlier submission would have earned more. |
| WCB Revenue Trend (line chart) | Monthly WCB revenue grouped by YYYY-MM. Revenue from wcb_invoice_lines sum. |
| WCB Rejection Rate (KPI card) | WCB-specific rejection rate: rejected / (assessed + paid + rejected + adjusted) for claim_type='WCB'. |

## 3.5 AI Coach Performance Dashboard

| Widget | Specification |
| --- | --- |
| Suggestion Acceptance Rate (KPI card) | accepted / (accepted + dismissed) from ai_suggestion_events filtered by event_type and created_at within period. |
| Revenue Recovered (KPI card) | Sum of revenue_impact for accepted suggestion events. The dollar value the AI Coach added. |
| Suggestions by Category (bar chart) | Count of suggestions generated per category from ai_suggestion_events. Stacked by status (accepted, dismissed, pending). |
| Top Accepted Suggestions (table) | Top 5 most frequently accepted rules. Joined to ai_rules for rule_name. Shows accepted count and total revenue impact. |
| Suppressed Rules (table) | Rules currently suppressed for this physician from ai_provider_learning where is_suppressed=TRUE. Joined to ai_rules for rule_name. Option to un-suppress from this view. |

## 3.6 Multi-Site Dashboard

For locum and multi-site physicians. Returns 404 if the physician has only one practice location (checked via `hasMultipleLocations(providerId)` dependency). Shows performance broken down by practice location.

| Widget | Specification |
| --- | --- |
| Revenue by Location (bar chart) | Revenue per practice location for the period. Joined via practice_locations.functional_centre to ahcip_claim_details.functional_centre. Filtered to is_active locations. |
| Claims by Location (table) | Claim count, revenue, rejection rate per location. Rejection rate computed as rejected / (assessed + paid + rejected + adjusted) per location. |
| RRNP Impact (KPI card) | RRNP rate per location from practice_locations.rrnp_rate. |
| Location Comparison (table) | All active locations shown. Optional compare_locations[] query parameter filters to specific location UUIDs (max 2 for side-by-side comparison). |

## 3.7 ARP Analytics Dashboard

For physicians enrolled in the ARP/APP shadow billing program. Provides dedicated analytics for shadow billing volumes and time-based medicine reporting.

| Widget | Specification |
| --- | --- |
| ARP Claims Total (KPI card) | Total ARP claims in the period, filtered separately from FFS claims. |
| TM Units Total (KPI card) | Total time units billed under ARP for the period. |
| ARP Rejection Rate (KPI card) | Rejection rate for ARP claims specifically. |
| Assessment Results (table) | ARP claim assessment outcomes: assessed, rejected, adjusted counts. |
| TM Summary Report | Per billing period breakdown: total time units by date and service type. Supports the physician's ARP program reporting obligations. |

## 3.8 Reciprocal Billing Dashboard

For physicians who treat out-of-province patients under interprovincial reciprocal billing agreements.

| Widget | Specification |
| --- | --- |
| Reciprocal Claim Volume (KPI card) | Total reciprocal billing claims by period. |
| Acceptance Rate by Province (table) | Success rates broken down by patient home province. |
| Province-Specific Rejection Patterns (table) | Common rejection reasons grouped by originating province. |
| Revenue from Reciprocal Patients (KPI card) | Total assessed revenue from reciprocal billing claims. |

# 4. Period Selection & Filtering

## 4.1 Time Periods

All dashboards (except Aging, which is point-in-time) support configurable time periods with prior-period comparison. Period resolution is handled by the `resolvePeriod()` function in the dashboard service, which computes exact date boundaries for both the current and comparison periods.

| Period | Default Range | Comparison |
| --- | --- | --- |
| THIS_WEEK | Monday to today | Same days last week |
| THIS_MONTH | 1st to today | Same days prior month (day clamped to last day of prior month) |
| LAST_MONTH | Full prior calendar month | Month before that |
| THIS_QUARTER | Q1/Q2/Q3/Q4 start to today | Same quarter prior year |
| THIS_YEAR | Jan 1 to today | Same period prior year (leap year aware) |
| CUSTOM_RANGE | User-selected start and end dates | Same-length period immediately prior |
| TRAILING_12_MONTHS | Today minus 12 months | 12 months before that |

The default period is THIS_MONTH. Period selection persists across dashboard tabs within the same session. Custom ranges require both `start_date` and `end_date` query parameters (validated by Zod refine). Maximum range: 730 days (2 years).

## 4.2 Filters

Dashboards support the following filters, applied globally across all widgets:

| Filter | Parameter | Validation |
| --- | --- | --- |
| Claim type | `claim_type` | Enum: AHCIP, WCB, BOTH (default: BOTH) |
| BA number | `ba_number` | String, max 20 chars. For PCPCM dual-BA physicians |
| Practice location | `location_id` | UUID. Filter to a specific practice location |
| Claim state | `claim_state` | Array of strings, max 30 chars each |
| HSC code | `hsc_code` | String, max 10 chars. Filter to a specific code or code range |

Filters are combinable. The claim_type filter is implemented as a SQL condition: `AND c.claim_type = ${claimType}` when not BOTH. The BA filter adds: `AND acd.ba_number = ${baNumber}`. An active filter indicator shows which filters are applied.

Not all filters apply to all dashboards. The aging dashboard accepts only `claim_type`. The WCB dashboard accepts `period` and `form_type`. The AI Coach dashboard accepts only `period`. The multi-site dashboard accepts `period` and `compare_locations[]`.

# 5. Caching Layer

## 5.1 Architecture

Analytics queries against claim data can be expensive for high-volume physicians. The caching layer pre-computes aggregate metrics and stores them in the `analytics_cache` table, avoiding repeated real-time aggregation on every dashboard load.

## 5.2 Cache Strategy

The cache operates on three refresh mechanisms:

**Nightly batch refresh:** The `refreshAllProviders()` method iterates all active providers, computes all metric keys for trailing 12 months, and bulk-upserts into the cache. Providers are processed in batches of 10 to limit database load.

**Event-driven incremental refresh:** The `handleClaimStateChange()` method is triggered when a claim transitions to a new state. It maps the claim's new state to affected metric keys using a predefined mapping:

| Claim State | Affected Metric Keys |
| --- | --- |
| paid | revenue_monthly, claims_paid, avg_fee_per_claim, revenue_by_ba, revenue_by_location, top_hsc_codes, pending_pipeline |
| rejected | rejection_rate_monthly, rejection_by_code, rejection_by_hsc, claims_rejected |
| submitted | claims_submitted, pending_pipeline |
| adjusted | claims_adjusted, rejection_resolution_funnel |

Event-driven refresh computes only the current month's values for affected metrics, providing near-real-time updates without full recomputation.

**Stale-cache detection on dashboard open:** When a physician opens the dashboard, the service checks whether any cache entries are older than 60 minutes (configurable via `CACHE_STALE_THRESHOLD_MINUTES`). If stale entries exist, a background refresh is triggered.

## 5.3 Cache Retention

Cache entries older than 24 months are eligible for hard deletion via `cleanupOldEntries()`. Hard deletes are permitted because the cache is not a PHI source of truth — all cached values can be recomputed from source claim tables.

## 5.4 Metric Keys

The following metric keys are pre-computed and cached:

| Category | Metric Keys |
| --- | --- |
| Revenue | revenue_monthly, revenue_by_ba, revenue_by_location, revenue_by_hsc |
| Claim Volume | claims_submitted, claims_assessed, claims_paid, claims_rejected, claims_adjusted |
| Rejection | rejection_rate_monthly, rejection_by_code, rejection_by_hsc, rejection_resolution_funnel |
| Aging | aging_brackets, approaching_deadline, expired_claims, avg_resolution_time, stale_claims |
| WCB | wcb_by_form_type, wcb_timing_tier_dist, wcb_fee_tier_analysis, wcb_revenue_trend, wcb_rejection_rate |
| AI Coach | ai_coach_acceptance_rate, ai_coach_revenue_recovered, ai_coach_by_category, ai_coach_top_accepted, ai_coach_suppressed |
| Multi-Site | multisite_revenue, multisite_claims, multisite_rrnp |
| Misc | pending_pipeline, avg_fee_per_claim, top_hsc_codes |

Each cache entry is keyed by: (provider_id, metric_key, period_start, period_end, dimensions). The dimensions JSONB column supports optional breakdown by ba_number, location_id, claim_type, or hsc_code. Null dimensions represent top-level aggregates.

# 6. Accountant Export

Physicians need to provide their accountants with billing summaries for tax preparation. The accountant export generates structured financial reports that accountants understand without Meritum-specific knowledge.

## 6.1 Export Formats

| Format | Description |
| --- | --- |
| CSV | Machine-readable. Suitable for import into accounting software (QuickBooks, Sage, Xero). One row per paid claim. |
| PDF Summary | Human-readable. Monthly or annual summary with totals, broken down by BA and location. Suitable for direct submission to accountant. |
| PDF Detailed | Human-readable. Individual claim details with dates, codes, fees. For detailed audit or tax filing. |

## 6.2 Accountant Export Fields

The CSV export includes one row per paid claim with columns: date_of_service, hsc_code, modifiers, submitted_fee, assessed_fee, payment_date, ba_number, location, claim_type. Fields containing commas, quotes, or newlines are escaped per RFC 4180. This allows the accountant to reconstruct revenue by any dimension.

The PDF summary report includes: physician name, BA numbers, period covered, total revenue, revenue by BA, revenue by location, AHCIP revenue, WCB revenue, claim count, RRNP premium total, adjustments (delta for adjusted claims), written-off total, and a GST exemption note.

## 6.3 Scheduled Accountant Reports

Physicians can configure automatic monthly accountant report generation:

Frequency: Monthly (generated on the 3rd business day of the following month, after all prior-month assessments have typically been received). Business days are computed as weekdays (Mon–Fri) excluding statutory holidays.

Format: PDF Summary + CSV (both generated)

Delivery: Email notification with authenticated download link. Files not attached to email (PHI protection). Link expires in 90 days (scheduled report retention).

Recipient: Physician only (physician forwards to accountant manually). Direct accountant email delivery deferred to future enhancement.

# 7. Data Portability Export

HIA and general data portability requirements mean physicians must be able to export their complete data from Meritum at any time. This export is separate from the accountant export and includes all data, not just financial summaries.

## 7.1 Export Contents

All claims: Every claim in every state, with full field data including AHCIP/WCB extension fields

All patients: Complete patient registry with demographics

Claim audit history: Every state change, edit, and action on every claim

AI Coach suggestions: All suggestions with acceptance/dismissal status and reasons

Batch history: All AHCIP and WCB batches with submission details

Provider profile: BA numbers, locations, WCB config, preferences

Export is a ZIP archive containing CSV files (one per table) plus a README.txt explaining the schema, data formats, and HIA compliance context. Optionally password-protected (minimum 12 characters enforced by Zod validation).

## 7.2 Export Process

Physician requests data portability export from settings. Requires `DATA_EXPORT` permission (distinct from `REPORT_EXPORT`).

System creates a `generated_reports` record with report_type=DATA_PORTABILITY, format=ZIP, status='pending'.

Report generation service sets status to 'generating', then assembles all CSV files via `getPortabilityData()` and creates a ZIP archive via the `ZipArchiver` abstraction.

On success, status is set to 'ready' with file path and size. On failure, status is set to 'failed' with a generic error message (no internal details exposed).

Physician notified when export is ready (in-app notification + optional email).

Download via authenticated, time-limited link (72-hour expiry, enforced by `download_link_expires_at`).

Export event audit-logged as `analytics.data_portability_requested` (sensitive action flagged).

Download event audit-logged as `analytics.data_portability_downloaded` (sensitive action flagged).

# 8. Report Generation Pipeline

## 8.1 Asynchronous Processing

All report generation is asynchronous. When a physician requests a report, the system creates a `generated_reports` record with status='pending' and returns the report_id immediately (HTTP 201). The actual generation is dispatched via `setImmediate()` to avoid blocking the request.

The report lifecycle follows a state machine: `pending` → `generating` → `ready` | `failed`.

## 8.2 Report Generation Service

The `createReportGenerationService` accepts injected dependencies for data access, file storage, PDF generation, and ZIP archiving. This design enables testing without filesystem or storage dependencies.

The `processReport()` dispatcher reads the report record, sets status to 'generating', then routes to the appropriate generator based on report_type:

| Report Type | Generator | Output |
| --- | --- | --- |
| ACCOUNTANT_SUMMARY (CSV) | generateAccountantCsv | CSV file with one row per paid claim |
| ACCOUNTANT_SUMMARY (PDF) | generateAccountantPdfSummary | PDF with revenue summary, BA/location breakdown |
| ACCOUNTANT_DETAIL (CSV) | generateAccountantCsv | Same CSV format |
| ACCOUNTANT_DETAIL (PDF) | generateAccountantPdfDetail | PDF with individual claim rows |
| DATA_PORTABILITY | generateDataPortabilityExport | Password-optional ZIP with 6 CSV files + README |

On failure, the report status is set to 'failed' with a generic error message: "Report generation failed. Please try again or contact support." No internal details, stack traces, or PHI are included in the error message.

## 8.3 Download Service

The `createDownloadService` manages secure file downloads for generated reports. It enforces:

**Provider scoping:** Report is fetched by (report_id, provider_id). If the report belongs to a different provider, 404 is returned (not 403, to avoid confirming existence).

**Status check:** Only reports with status='ready' are downloadable. Pending, generating, or failed reports return 404.

**Link expiry:** If `download_link_expires_at` has passed, a 410 Gone response is returned with message "Download link has expired".

**Content-type mapping:** CSV → text/csv, PDF → application/pdf, ZIP → application/zip.

**Download tracking:** After streaming the file, the report is marked as downloaded (`downloaded=true`) and an audit log entry is created.

**Expired file cleanup:** The `cleanupExpiredFiles()` method deletes physical files for expired reports and updates their DB status to 'expired'. Called by a cleanup cron job. Physical file deletion is attempted first; if the file is already gone, the DB update proceeds.

# 9. Scheduled Reports

Beyond the accountant export, physicians can subscribe to automated recurring reports delivered via notification. Subscriptions are managed through a dedicated CRUD API.

## 9.1 Available Scheduled Reports

| Report | Frequency | Schedule | Content |
| --- | --- | --- | --- |
| Weekly Billing Summary | WEEKLY | Every Monday | Prior week: claims created, submitted, assessed, rejected. Revenue. Rejection rate. Approaching deadlines. |
| Monthly Performance Report | MONTHLY | 3rd business day of month | Prior month: full revenue breakdown, rejection analysis, AI Coach summary, claim aging status. |
| RRNP Quarterly Summary | QUARTERLY | After each quarter end | RRNP premium earned by location for the prior quarter. Useful for physicians tracking rural incentive. |
| WCB Timing Report | WEEKLY | Every Wednesday | WCB claims approaching timing tier downgrades in the next 7 days. Urgency-sorted. |
| Rejection Alert Digest | DAILY | Daily (if any) | New rejections received in the past 24 hours with rejection codes and corrective guidance. Skipped if no rejections in the past 24 hours. |

Subscribable report types are a restricted subset — DATA_PORTABILITY, ACCOUNTANT_SUMMARY, and ACCOUNTANT_DETAIL are excluded from subscription (they are on-demand only).

## 9.2 Subscription Model

Each physician can have one subscription per report type (enforced by unique constraint on provider_id + report_type). A subscription specifies:

- **report_type**: Which report to generate (from subscribable types)
- **frequency**: DAILY, WEEKLY, MONTHLY, or QUARTERLY
- **delivery_method**: IN_APP (default), EMAIL, or BOTH
- **is_active**: Active subscriptions generate reports on schedule; inactive ones are paused

Subscriptions are hard-deleted on cancellation (DELETE endpoint), not soft-deleted.

## 9.3 Schedule Processing

The `createScheduledReportsService` is called by cron jobs at appropriate intervals:

**Daily processing:** Fetches all active DAILY subscriptions. For REJECTION_DIGEST, checks `hasRejectionsInPeriod()` via the injected `RejectionChecker` — if no rejections in the past 24 hours, the subscription is skipped (per FRD: "Daily (if any)").

**Weekly processing:** Fetches all active WEEKLY subscriptions. Filters by day of week: WEEKLY_SUMMARY only runs on Monday (dayOfWeek=1), WCB_TIMING only runs on Wednesday (dayOfWeek=3). Period is prior week (Mon–Sun) for summaries, upcoming 7 days for WCB timing alerts.

**Monthly processing:** Fetches all active MONTHLY subscriptions. Only processes on the 3rd business day of the month (computed via `getNthBusinessDay()`). Period covers the prior month.

**Quarterly processing:** Fetches all active QUARTERLY subscriptions. Period covers the prior quarter (Q1=Jan–Mar, Q2=Apr–Jun, Q3=Jul–Sep, Q4=Oct–Dec).

## 9.4 Report Delivery

For each processed subscription:

1. A `generated_reports` record is created with `scheduled=true`
2. The report is generated via `processReport()`
3. An in-app notification is always sent via `sendReportReadyNotification()`
4. If delivery_method is EMAIL or BOTH, an email notification is sent via `sendReportReadyEmail()` with authenticated download link (no report content in email body, per PHI protection requirements)

Reports are generated as PDF (default format for scheduled reports). Download links expire after 90 days. Physicians configure which reports they want and delivery preferences through the subscription API.

# 10. Data Model

Analytics does not maintain its own copy of claim data. It queries the source tables in Domain 4 and related domains at read time, with pre-computed aggregates cached in the analytics_cache table for performance.

## 10.1 Analytics Cache Table (analytics_cache)

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| cache_id | UUID | No | Primary key (defaultRandom) |
| provider_id | UUID FK | No | FK to providers. Physician scoping key. |
| metric_key | VARCHAR(50) | No | Metric identifier (e.g., 'revenue_monthly', 'rejection_rate_monthly') |
| period_start | DATE | No | Start of the period this metric covers (YYYY-MM-DD string mode) |
| period_end | DATE | No | End of the period |
| dimensions | JSONB | Yes | Breakdown dimensions: {ba_number?, location_id?, claim_type?, hsc_code?}. Null for top-level aggregates. |
| value | JSONB | No | Metric value(s). Structure varies by metric_key. |
| computed_at | TIMESTAMPTZ | No | When this cache entry was last computed. Default: now(). |

**Indexes:**
- Unique: (provider_id, metric_key, period_start, period_end, dimensions) — upsert target
- Composite: (provider_id, metric_key) — dashboard queries
- Single: (computed_at) — stale cache detection

**Refresh strategy:** Cache is refreshed: (1) nightly batch for all metrics across trailing 12 months, (2) incrementally when a claim state changes (current month only, affected metrics only), (3) when the physician opens the dashboard and the cache is >1 hour old. Current-day metrics are computed in real-time (cache covers completed periods only).

## 10.2 Generated Reports Table (generated_reports)

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| report_id | UUID | No | Primary key (defaultRandom) |
| provider_id | UUID FK | No | FK to providers. Physician scoping key. |
| report_type | VARCHAR(50) | No | ACCOUNTANT_SUMMARY, ACCOUNTANT_DETAIL, WEEKLY_SUMMARY, MONTHLY_PERFORMANCE, RRNP_QUARTERLY, WCB_TIMING, REJECTION_DIGEST, DATA_PORTABILITY |
| format | VARCHAR(10) | No | PDF, CSV, ZIP |
| period_start | DATE | Yes | Period covered (null for data portability, string mode) |
| period_end | DATE | Yes | Period covered (null for data portability, string mode) |
| file_path | VARCHAR(255) | No | Path to generated file in object storage (encrypted at rest). Never exposed in API responses. |
| file_size_bytes | BIGINT | No | File size for download progress indication (number mode) |
| download_link_expires_at | TIMESTAMPTZ | No | When the download link expires |
| downloaded | BOOLEAN | No | Whether the physician has downloaded this report. Default: false. |
| scheduled | BOOLEAN | No | True if generated by scheduled report. False if on-demand. Default: false. |
| status | VARCHAR(20) | No | Report lifecycle: pending, generating, ready, failed, expired. Default: pending. |
| error_message | TEXT | Yes | Generic error message on failure. Never contains PHI or internal details. |
| created_at | TIMESTAMPTZ | No | Default: now(). |

**Indexes:**
- Composite: (provider_id, report_type) — listing reports by type
- Composite: (provider_id, created_at) — recent reports listing
- Single: (download_link_expires_at) — cleanup job for expired links
- Single: (status) — processing queue queries

**Retention:** Generated reports retained for 90 days (scheduled) or 30 days (on-demand). Data portability exports retained for 72 hours (3 days) after generation. Expired reports are cleaned up by the `cleanupExpiredFiles()` cron job.

## 10.3 Report Subscriptions Table (report_subscriptions)

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| subscription_id | UUID | No | Primary key (defaultRandom) |
| provider_id | UUID FK | No | FK to providers. Physician scoping key. |
| report_type | VARCHAR(50) | No | Which report to generate (subscribable types only) |
| frequency | VARCHAR(20) | No | DAILY, WEEKLY, MONTHLY, QUARTERLY |
| delivery_method | VARCHAR(20) | No | IN_APP (default), EMAIL, BOTH |
| is_active | BOOLEAN | No | Active subscriptions generate reports on schedule. Default: true. |
| created_at | TIMESTAMPTZ | No | Default: now(). |
| updated_at | TIMESTAMPTZ | No | Default: now(). Updated on every modification. |

**Indexes:**
- Unique: (provider_id, report_type) — one subscription per report type per physician
- Composite: (is_active, frequency) — scheduled job queries for due subscriptions

**Constraint behavior:** Creating a duplicate subscription (same provider + report type) triggers a PostgreSQL 23505 unique violation, returned to the client as HTTP 409 Conflict.

# 11. User Stories & Acceptance Criteria

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| ANL-001 | As a physician, I want to see my revenue dashboard so I can understand my billing performance | Dashboard loads in < 2 seconds. KPI cards show current period vs prior. Revenue trend chart shows monthly data. Filterable by claim type, BA, location. |
| ANL-002 | As a physician, I want to understand why claims are being rejected | Rejection dashboard shows top explanatory codes, rejection rate, per-HSC rejection rates. Resolution funnel shows recovery path. |
| ANL-003 | As a physician, I want to see claims approaching their submission deadline | Aging dashboard shows deadline-approaching claims with days remaining. Sorted by urgency. Click to navigate to claim. |
| ANL-004 | As a physician, I want to export a financial summary for my accountant | Select period. Choose format (CSV / PDF Summary / PDF Detailed). Generate async and download. CSV includes per-claim detail. |
| ANL-005 | As a physician, I want automatic monthly reports sent to me | Configure report subscription via API. Monthly PDF generated automatically on 3rd business day. Notification with download link. |
| ANL-006 | As a physician, I want to export all my data from Meritum | Data portability export from settings. Generates ZIP with all claims, patients, audit history, AI suggestions, batches, provider profile. Download via secure link within 72 hours. |
| ANL-007 | As a locum physician, I want to compare billing performance across my practice locations | Multi-site dashboard shows per-location revenue, claims, rejection rates. Up to 2 locations for side-by-side comparison. |
| ANL-008 | As a physician, I want to see how much revenue the AI Coach has recovered for me | AI Coach dashboard shows acceptance rate, total revenue impact of accepted suggestions, suggestions by category, top accepted rules, suppressed rules. |
| ANL-009 | As a physician who bills WCB, I want to understand my timing tier performance | WCB dashboard shows timing tier distribution, fee impact analysis per tier, form type breakdown, WCB rejection rate. |
| ANL-010 | As a delegate, I want to view reports on behalf of my physician | Requires ANALYTICS_VIEW for dashboards, REPORT_VIEW for report status, REPORT_EXPORT for downloads, DATA_EXPORT for data portability. All scoped to the physician context. |
| ANL-011 | As an ARP physician, I want to track my shadow billing volumes | ARP analytics dashboard shows total ARP claims, TM units, rejection rate. TM summary report available for program reporting obligations. |
| ANL-012 | As a physician treating out-of-province patients, I want to track reciprocal billing performance | Reciprocal billing reporting shows claim volumes, acceptance rates by province, province-specific rejection patterns. |

# 12. API Contracts

All endpoints require authentication and are scoped to the physician (or delegate's active physician context). Permission guards are enforced via Fastify preHandler hooks.

## 12.1 Dashboard Data

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| GET | /api/v1/analytics/revenue | ANALYTICS_VIEW | Revenue dashboard data. Query: period, start_date, end_date, claim_type, ba_number, location_id, claim_state[], hsc_code. Returns current data, comparison data, delta, period bounds, cache status. |
| GET | /api/v1/analytics/rejections | ANALYTICS_VIEW | Rejection analysis data. Query: period, start_date, end_date, claim_type, hsc_code. Returns current + comparison + delta. |
| GET | /api/v1/analytics/aging | ANALYTICS_VIEW | Claim aging data (real-time, no period). Query: claim_type. Returns brackets, approaching deadline, expired, avg resolution, stale claims. |
| GET | /api/v1/analytics/wcb | ANALYTICS_VIEW | WCB analytics data. Query: period, start_date, end_date, form_type. Returns 404 if physician has no WCB config. |
| GET | /api/v1/analytics/ai-coach | ANALYTICS_VIEW | AI Coach performance metrics. Query: period, start_date, end_date. Returns current + comparison + delta. |
| GET | /api/v1/analytics/multi-site | ANALYTICS_VIEW | Multi-site breakdown. Query: period, start_date, end_date, compare_locations[] (max 2 UUIDs). Returns 404 if physician has single location. |
| GET | /api/v1/analytics/kpis | ANALYTICS_VIEW | All KPI card values for the selected period. Single call for dashboard init. Query: period, start_date, end_date, claim_type, ba_number, location_id, claim_state[], hsc_code. |
| GET | /api/v1/analytics/arp-summary | ANALYTICS_VIEW | ARP-specific analytics summary. Query: period (this_month, last_month, custom). Returns total claims, TM units, rejection rate. |
| GET | /api/v1/analytics/arp-tm-report | ANALYTICS_VIEW | TM summary report per billing period. Query: startDate, endDate. Returns time units by date and service type. |

All dashboard endpoints return data wrapped in `{ data: ... }` with additional `period`, `comparison`, `delta`, and `cacheStatus` fields where applicable. The `cacheStatus` field indicates whether the response was served from cache ('fresh'), triggered a background refresh ('stale'), or computed in real-time ('realtime').

**Audit logging:** Dashboard views are audit-logged with rate limiting — maximum 1 audit log entry per dashboard type per 5 minutes per physician, to avoid audit noise from frequent tab switching. Rate limiting is enforced via an in-memory timestamp map.

## 12.2 Reports

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| POST | /api/v1/reports/accountant | REPORT_EXPORT | Generate accountant export. Body: { period_start: YYYY-MM-DD, period_end: YYYY-MM-DD, format: csv|pdf_summary|pdf_detail }. Max range 2 years. Returns { data: { report_id, status: 'pending' } }. HTTP 201. |
| POST | /api/v1/reports/data-portability | DATA_EXPORT | Request full data portability export. Body: { password?: string (min 12 chars) }. Returns { data: { report_id, status: 'pending' } }. HTTP 201. Audit: sensitive action flagged. |
| GET | /api/v1/reports/:id | REPORT_VIEW | Check report status. Returns sanitized report object (report_id, report_type, format, status, period, file_size, expiry, downloaded, created_at). file_path never exposed. |
| GET | /api/v1/reports/:id/download | REPORT_EXPORT | Stream file download. Returns file with Content-Type, Content-Disposition, Content-Length headers. 404 if not found/wrong provider/not ready. 410 if expired. Audit: REPORT_DOWNLOADED or DATA_PORTABILITY_DOWNLOADED. |
| GET | /api/v1/reports | REPORT_VIEW | List generated reports for the physician. Query: report_type, start_date, end_date, limit (1-100, default 20), offset (default 0). Returns paginated response: { data: [...], pagination: { total, page, pageSize, hasMore } }. |

## 12.3 Report Subscriptions

| Method | Endpoint | Permission | Description |
| --- | --- | --- | --- |
| GET | /api/v1/report-subscriptions | REPORT_VIEW | List all active and inactive subscriptions for the physician. |
| POST | /api/v1/report-subscriptions | REPORT_EXPORT | Create a subscription. Body: { report_type (subscribable only), frequency, delivery_method (default: IN_APP) }. 409 if duplicate. HTTP 201. Audit: subscription_created. |
| PUT | /api/v1/report-subscriptions/:id | REPORT_EXPORT | Update a subscription (frequency, delivery_method, is_active). At least one field required. 404 if not found/wrong provider. Audit: subscription_updated. |
| DELETE | /api/v1/report-subscriptions/:id | REPORT_EXPORT | Cancel (hard delete) a subscription. 204 on success. 404 if not found/wrong provider. Audit: subscription_cancelled. |

# 13. Validation Schemas

All Zod validation schemas are defined in `packages/shared/src/schemas/validation/analytics.validation.ts` and shared between API and frontend.

## 13.1 Dashboard Query Schemas

| Schema | Fields | Refinements |
| --- | --- | --- |
| revenueQuerySchema | period, start_date?, end_date?, claim_type?, ba_number?, location_id?, claim_state[]?, hsc_code? | start_date + end_date required for CUSTOM_RANGE; range ≤ 730 days |
| rejectionQuerySchema | period, start_date?, end_date?, claim_type?, hsc_code? | Same period refinements |
| agingQuerySchema | claim_type? | No period (point-in-time) |
| wcbQuerySchema | period, start_date?, end_date?, form_type? | Same period refinements |
| aiCoachQuerySchema | period, start_date?, end_date? | Same period refinements |
| multiSiteQuerySchema | period, start_date?, end_date?, compare_locations[]? | Max 2 location UUIDs; same period refinements |
| kpiQuerySchema | period, start_date?, end_date?, claim_type?, ba_number?, location_id?, claim_state[]?, hsc_code? | Same period refinements |

## 13.2 Report Schemas

| Schema | Fields | Validation |
| --- | --- | --- |
| accountantReportSchema | period_start, period_end, format | Dates as YYYY-MM-DD; format enum: csv, pdf_summary, pdf_detail; range ≤ 730 days |
| dataPortabilitySchema | password? | Optional; if provided, min 12 characters |
| reportIdParamSchema | id | UUID format |
| reportListQuerySchema | report_type?, start_date?, end_date?, limit, offset | limit: 1–100 (default 20), offset: ≥0 (default 0); coerced from query string |

## 13.3 Subscription Schemas

| Schema | Fields | Validation |
| --- | --- | --- |
| createSubscriptionSchema | report_type, frequency, delivery_method | report_type restricted to subscribable types (excludes DATA_PORTABILITY, ACCOUNTANT_*); frequency enum; delivery_method default IN_APP |
| updateSubscriptionSchema | frequency?, delivery_method?, is_active? | At least one field required (Zod refine) |
| subscriptionIdParamSchema | id | UUID format |

# 14. Performance Requirements

## 14.1 Dashboard Load Time

Target: Dashboard initial load < 2 seconds for physicians with < 5,000 claims

Strategy: Pre-computed cache for completed periods. Real-time computation only for current-day data. Cache entries keyed by provider + metric + period + dimensions for efficient lookup.

Cache refresh: Nightly batch (all providers, trailing 12 months) + event-driven incremental (current month, affected metrics only) + stale-cache detection (>60 minutes triggers background refresh).

## 14.2 Report Generation Time

Report generation is asynchronous. The physician receives a notification when the report is ready. The API immediately returns report_id with status 'pending' (HTTP 201).

| Report Type | Expected Size | Target Time |
| --- | --- | --- |
| Accountant CSV (monthly) | ~500 rows | < 5 seconds |
| Accountant PDF summary | 2–4 pages | < 10 seconds |
| Accountant PDF detailed (annual) | ~6,000 rows / 50+ pages | < 60 seconds |
| Data portability export | All data (potentially 10+ years) | < 5 minutes |

## 14.3 Data Volume Estimates

| Metric | Estimate |
| --- | --- |
| Claims per physician per month | 50–300 (GP), 100–500 (specialist), 500–2,000 (ED/radiologist) |
| Claims per physician lifetime | 5,000–50,000 over 5–10 years |
| Aggregate cache entries per physician | ~500 (12 months × ~40 metric_keys) |
| Generated reports per physician per year | 12 monthly + 52 weekly + on-demand = ~80–100 |

# 15. Security & Audit

## 15.1 Data Protection

Analytics data is derived from PHI (claim data includes patient information). All analytics queries, cache, and reports encrypted at rest and in transit.

Dashboard data is physician-scoped at the query level. Every SQL query in `dashboard-query.repo.ts` includes `WHERE c.physician_id = ${providerId}` (or equivalent provider_id condition). No cross-physician data access.

Generated reports contain PHI (per-claim detail includes patient PHN in CSV exports). Reports encrypted at rest in object storage. Download links authenticated and time-limited. The `file_path` column is never exposed in API responses — the sanitizeReport() helper strips it.

Data portability exports are the most sensitive output. Optional password encryption. 72-hour download window. Both request and download events are audit-logged as sensitive actions.

Accountant exports are delivered via authenticated download link only. Never emailed as attachments. No PHI in email bodies.

Server version headers are stripped (no x-powered-by, no server header). 500 errors return generic "Internal server error" with no stack traces, SQL references, or internal details.

Specialty cohort comparisons (future enhancement) use only anonymised, aggregated data with minimum cohort size requirements.

## 15.2 Permission Model

| Permission | Grants Access To |
| --- | --- |
| ANALYTICS_VIEW | All 7+ dashboard endpoints (revenue, rejections, aging, WCB, AI Coach, multi-site, KPIs, ARP) |
| REPORT_VIEW | Report status check (GET /reports/:id), report listing (GET /reports), subscription listing (GET /report-subscriptions) |
| REPORT_EXPORT | Report generation (POST /reports/accountant), report download (GET /reports/:id/download), subscription management (POST/PUT/DELETE /report-subscriptions) |
| DATA_EXPORT | Data portability export (POST /reports/data-portability). Separated from REPORT_EXPORT due to sensitivity. |

Delegates access dashboards and reports through their physician context. The `getProviderId()` helper extracts the provider_id from the auth context, returning `delegateContext.physicianProviderId` for delegates and `userId` for direct physician access.

## 15.3 Audit Trail

| Action | Audit Key | Details Logged |
| --- | --- | --- |
| Dashboard viewed | analytics.dashboard_viewed | Dashboard type, period, filters applied. Rate-limited: max 1 log per dashboard type per 5 min per physician. |
| Report generated | analytics.report_generated | Report ID, type, format, period. |
| Report downloaded | analytics.report_downloaded | Report ID, type, format. |
| Data portability requested | analytics.data_portability_requested | Report ID. Sensitive action flagged. |
| Data portability downloaded | analytics.data_portability_downloaded | Report ID. Sensitive action flagged. |
| Subscription created | analytics.subscription_created | Subscription ID, report type, frequency, delivery method. |
| Subscription updated | analytics.subscription_updated | Subscription ID, changed fields. |
| Subscription cancelled | analytics.subscription_cancelled | Subscription ID. |

# 16. Testing Requirements

## 16.1 Dashboard Tests

Revenue dashboard with known claim data → KPI values match expected calculations

Period comparison: this month vs last month → correct delta values (percentage change computation verified)

Rejection dashboard: rejection rate calculated correctly (rejected / (assessed + rejected + adjusted))

Aging brackets: claims correctly categorised by days since DOS (0–30, 31–60, 61–90, 90+)

Filter application: claim_type filter shows only AHCIP or WCB claims (SQL condition verified)

PCPCM dual-BA: revenue by BA correctly splits between PCPCM and FFS

Multi-site: per-location breakdown matches per-location claim totals (functional_centre join verified)

WCB timing tier distribution: claims correctly assigned to timing tiers from validation_result JSONB

AI Coach metrics: acceptance rate matches suggestion event data (generated/accepted/dismissed counts)

Period resolution: all 7 period types produce correct date boundaries and comparison periods

## 16.2 Report Generation Tests

Accountant CSV: all paid claims in period included, correct fee values, correct column headers, CSV escaping correct

Accountant PDF summary: totals match CSV data, BA breakdown correct, location breakdown correct

Data portability: all 6 CSV tables exported plus README, row counts match source, schema README accurate

Large dataset: 10,000 claims → export completes within target time

Report status lifecycle: pending → generating → ready (file path and size set) | failed (generic error message)

## 16.3 Scheduled Report Tests

Monthly subscription: report generated on 3rd business day of month (business day computation verified)

Weekly subscription: WEEKLY_SUMMARY only on Monday, WCB_TIMING only on Wednesday

Daily rejection digest: skipped when no rejections in past 24 hours

Notification delivered with download link (in-app always, email when delivery_method is EMAIL or BOTH)

Download link expires after configured period (90 days for scheduled, 30 for on-demand, 3 for data portability)

Inactive subscription: no report generated

409 on duplicate subscription creation (same provider + report type)

## 16.4 Cache Tests

Nightly batch: all metric keys computed for trailing 12 months, bulk-upserted

Event-driven refresh: claim state change triggers incremental refresh for affected metrics (current month only)

Stale detection: cache entries older than 60 minutes detected correctly

Cleanup: entries older than 24 months deleted

Upsert: duplicate (provider, metric, period, dimensions) updates value and computed_at

## 16.5 Integration Tests

Create claims → submit → assess → verify dashboard reflects new data within cache refresh window

Reject claim → verify rejection dashboard updates

Accept AI Coach suggestion → verify AI Coach dashboard shows acceptance

Delegate with ANALYTICS_VIEW → can view dashboards. Without permission → denied.

Delegate with REPORT_VIEW → can view report list and status. Without permission → denied.

Delegate with REPORT_EXPORT → can download reports. Without permission → denied.

Delegate with DATA_EXPORT → can request data portability. Without permission → denied.

## 16.6 Download Tests

Download ready report → file streams with correct content-type and content-disposition

Download expired report → 410 Gone

Download non-existent report → 404

Download another physician's report → 404 (not 403)

Download pending/failed report → 404

# 17. Open Questions

| # | Question | Context |
| --- | --- | --- |
| 1 | Should anonymised specialty benchmarking be an MVP feature or deferred? | Comparing a physician's rejection rate or revenue per claim to their specialty average could be valuable but requires sufficient user base and privacy framework. |
| 2 | Should the accountant export support direct delivery to accountant email? | Would require the physician to configure accountant email and consent to external delivery of PHI-containing reports. MVP: physician downloads and forwards. |
| 3 | What retention period is appropriate for generated reports? | Current implementation: 90 days (scheduled), 30 days (on-demand), 72 hours (data portability). May need to align with HIA retention requirements. |
| 4 | Should analytics support year-over-year comparison on the same chart? | Useful for identifying seasonal trends but adds UI complexity. MVP: prior-period comparison only. |
| 5 | What is the right cache refresh strategy for physicians with very high claim volumes (radiologists)? | Nightly batch may be insufficient for 2,000+ claims/month. Event-driven incremental refresh partially addresses this. May need more frequent batch intervals for high-volume providers. |
| 6 | Should ARP analytics and reciprocal billing reporting be separate dashboard tabs or integrated into existing dashboards as filters? | Current design: separate dashboard sections. Alternative: additional filter values on revenue/rejection dashboards. |

# 18. Document Control

This domain is read-only. It consumes data from the Claim Lifecycle, Provider Management, Reference Data, and Intelligence Engine. It produces dashboards, reports, and exports but never modifies source data.

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | Analytics & Reporting (Domain 8 of 13) |
| Build sequence position | 8th |
| Dependencies | Domain 1 (IAM), Domain 2 (Reference Data), Domain 4 (Claim Lifecycle), Domain 5 (Provider Mgmt), Domain 7 (Intelligence Engine) |
| Consumed by | Domain 9 (Notification Service for scheduled report delivery) |
| Version | 2.0 |
| Date | February 2026 |
| Next domain in critical path | Domain 9 (Notification Service) |

### Version History

| Version | Date | Changes |
| --- | --- | --- |
| 1.0 | February 2026 | Initial FRD |
| 2.0 | February 2026 | Synced with implementation: documented subdirectory module architecture (repos/, routes/, services/), caching layer with nightly batch + event-driven + stale detection, report subscription model with scheduled processing, download service with expiry enforcement, report generation pipeline with async lifecycle, validation schemas. Added ARP analytics and reciprocal billing reporting sections per MVP Features Addendum (B5, B8). Updated data model with Drizzle schema details, indexes, and constraints. Expanded API contracts with permission guards, query parameters, and response shapes. Added cache metric key inventory. |
