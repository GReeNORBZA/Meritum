# Meritum_Domain_08_Analytics_Reporting

MERITUM

Functional Requirements

Analytics & Reporting

Domain 8 of 13  |  Critical Path: Position 8

Meritum Health Technologies Inc.

Version 1.0  |  February 2026

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

Accountant export: structured financial summaries for tax preparation

Data portability export: complete claim history export per HIA data portability requirements

Scheduled reports: automated weekly/monthly report generation and delivery

## 1.3 Out of Scope

Claim modification or state changes (Domain 4 Claim Lifecycle)

Real-time claim monitoring (Domain 4; Analytics shows historical/aggregate views)

AI suggestion generation (Domain 7 Intelligence Engine; Analytics shows acceptance metrics)

Cross-physician benchmarking with identified data (privacy constraint; only anonymised specialty cohort comparisons)

## 1.4 Domain Dependencies

# 2. Dashboard Specifications

The analytics dashboard is the physician's primary view of their billing performance. It is designed for at-a-glance comprehension with drill-down capability. All dashboard data is scoped to the authenticated physician.

## 2.1 Revenue Overview Dashboard

The default landing view. Shows aggregate financial performance.

## 2.2 Rejection Analysis Dashboard

## 2.3 Claim Aging Dashboard

## 2.4 WCB Analytics Dashboard

Visible only to physicians with WCB configuration (Domain 5).

## 2.5 AI Coach Performance Dashboard

## 2.6 Multi-Site Dashboard

For locum and multi-site physicians. Shows performance broken down by practice location.

# 3. Period Selection & Filtering

## 3.1 Time Periods

All dashboards support configurable time periods with prior-period comparison:

The default period is 'This Month'. Period selection persists across dashboard tabs within the same session.

## 3.2 Filters

Dashboards support the following filters, applied globally across all widgets:

Claim type: AHCIP, WCB, or Both (default: Both)

BA number: Filter to a specific BA (for PCPCM dual-BA physicians)

Practice location: Filter to a specific practice location

Claim state: Filter to specific states (e.g., show only rejected claims)

HSC code: Filter to a specific code or code range

Filters are combinable. An active filter indicator shows which filters are applied.

# 4. Accountant Export

Physicians need to provide their accountants with billing summaries for tax preparation. The accountant export generates structured financial reports that accountants understand without Meritum-specific knowledge.

## 4.1 Export Formats

## 4.2 Accountant Export Fields

The CSV export includes one row per paid claim with: date_of_service, HSC code, modifier(s), submitted_fee, assessed_fee, payment_date, BA_number, location, claim_type. This allows the accountant to reconstruct revenue by any dimension.

## 4.3 Scheduled Accountant Reports

Physicians can configure automatic monthly accountant report generation:

Frequency: Monthly (generated on the 3rd business day of the following month, after all prior-month assessments have typically been received)

Format: PDF Summary + CSV (both generated)

Delivery: Email notification with authenticated download link. Files not attached to email (PHI protection). Link expires in 30 days.

Recipient: Physician only (physician forwards to accountant manually). Direct accountant email delivery deferred to future enhancement.

# 5. Data Portability Export

HIA and general data portability requirements mean physicians must be able to export their complete data from Meritum at any time. This export is separate from the accountant export and includes all data, not just financial summaries.

## 5.1 Export Contents

All claims: Every claim in every state, with full field data including AHCIP/WCB extension fields

All patients: Complete patient registry with demographics

Claim audit history: Every state change, edit, and action on every claim

AI Coach suggestions: All suggestions with acceptance/dismissal status and reasons

Batch history: All AHCIP and WCB batches with submission details

Provider profile: BA numbers, locations, WCB config, preferences

Export is a ZIP archive containing CSV files (one per table) plus a README explaining the schema. Optionally includes JSON format for machine consumption.

## 5.2 Export Process

Physician requests data portability export from settings.

System generates export asynchronously (may take minutes for large datasets).

Physician notified when export is ready.

Download via authenticated, time-limited link (72-hour expiry).

Export file encrypted with physician-provided password (optional but recommended).

Export event audit-logged.

# 6. Scheduled Reports

Beyond the accountant export, physicians can subscribe to automated recurring reports delivered via notification.

## 6.1 Available Scheduled Reports

## 6.2 Report Delivery

Reports delivered as in-app notification with link to the generated report.

Optionally accompanied by email notification with authenticated download link (no report content in email body).

Physician configures which reports they want and delivery preferences in settings.

Reports are generated as PDF and stored for 90 days. Older reports are archived.

# 7. Data Model

Analytics does not maintain its own copy of claim data. It queries the source tables in Domain 4 and related domains at read time, with pre-computed aggregates cached for performance.

## 7.1 Analytics Cache Table (analytics_cache)

Pre-computed aggregate metrics refreshed periodically. Avoids expensive real-time aggregation on every dashboard load.

Refresh strategy: Cache is refreshed: (1) nightly for all metrics, (2) on-demand when a claim state changes that affects a displayed metric, (3) when the physician opens the dashboard and the cache is >1 hour old. Current-day metrics are always computed in real-time (cache covers completed periods only).

## 7.2 Generated Reports Table (generated_reports)

Retention: Generated reports retained for 90 days (scheduled) or 30 days (on-demand). Data portability exports retained for 72 hours after generation.

## 7.3 Report Subscriptions Table (report_subscriptions)

# 8. User Stories & Acceptance Criteria

# 9. API Contracts

All endpoints require authentication and are scoped to the physician (or delegate's active physician context). Delegate permissions REPORT_VIEW and REPORT_EXPORT enforced by Domain 1.

## 9.1 Dashboard Data

## 9.2 Reports

## 9.3 Report Subscriptions

# 10. Performance Requirements

## 10.1 Dashboard Load Time

Target: Dashboard initial load < 2 seconds for physicians with < 5,000 claims

Strategy: Pre-computed cache for completed periods. Real-time computation only for current-day data.

Cache refresh: Nightly batch + event-driven incremental updates + stale-cache detection on dashboard open.

## 10.2 Report Generation Time

Report generation is asynchronous. The physician receives a notification when the report is ready. Progress indication shown for long-running exports.

## 10.3 Data Volume Estimates

# 11. Security & Audit

## 11.1 Data Protection

Analytics data is derived from PHI (claim data includes patient information). All analytics queries, cache, and reports encrypted at rest and in transit.

Dashboard data is physician-scoped at the query level. No cross-physician data access.

Generated reports contain PHI (per-claim detail includes patient PHN in CSV exports). Reports encrypted at rest. Download links authenticated and time-limited.

Data portability exports are the most sensitive output. Optional password encryption. 72-hour download window.

Accountant exports are delivered via authenticated download link only. Never emailed as attachments.

Specialty cohort comparisons (future enhancement) use only anonymised, aggregated data with minimum cohort size requirements.

## 11.2 Audit Trail

# 12. Testing Requirements

## 12.1 Dashboard Tests

Revenue dashboard with known claim data → KPI values match expected calculations

Period comparison: this month vs last month → correct delta values

Rejection dashboard: rejection rate calculated correctly (rejected / (assessed + rejected + adjusted))

Aging brackets: claims correctly categorised by days since DOS

Filter application: claim_type filter shows only AHCIP or WCB claims

PCPCM dual-BA: revenue by BA correctly splits between PCPCM and FFS

Multi-site: per-location breakdown matches per-location claim totals

WCB timing tier distribution: claims correctly assigned to timing tiers

AI Coach metrics: acceptance rate matches suggestion event data

## 12.2 Report Generation Tests

Accountant CSV: all paid claims in period included, correct fee values, correct column headers

Accountant PDF summary: totals match CSV data, BA breakdown correct, location breakdown correct

Data portability: all tables exported, row counts match source, schema README accurate

Large dataset: 10,000 claims → export completes within target time

## 12.3 Scheduled Report Tests

Monthly subscription: report generated on schedule (3rd business day of month)

Notification delivered with download link

Download link expires after configured period (30 or 90 days)

Inactive subscription: no report generated

## 12.4 Integration Tests

Create claims → submit → assess → verify dashboard reflects new data within cache refresh window

Reject claim → verify rejection dashboard updates

Accept AI Coach suggestion → verify AI Coach dashboard shows acceptance

Delegate with REPORT_VIEW → can view dashboards. Without permission → denied.

Delegate with REPORT_EXPORT → can download reports. Without permission → denied.

# 13. Open Questions

# 14. Document Control

This domain is read-only. It consumes data from the Claim Lifecycle, Provider Management, Reference Data, and Intelligence Engine. It produces dashboards, reports, and exports but never modifies source data.

| Domain | Direction | Interface |
| --- | --- | --- |
| 1 Identity & Access | Consumed | Authentication, RBAC. Reports scoped to physician. Delegates with REPORT_VIEW/REPORT_EXPORT permissions. |
| 2 Reference Data | Consumed | HSC code descriptions, explanatory code descriptions, modifier names for human-readable report labels. |
| 4.0 Claim Lifecycle Core | Consumed | Claim data: states, dates, fees, validation results. The primary data source. |
| 4.1 AHCIP Pathway | Consumed | AHCIP batch history, assessment results, explanatory codes, PCPCM routing data. |
| 4.2 WCB Pathway | Consumed | WCB claim data: form types, timing tiers, fee calculations, return file results. |
| 5 Provider Management | Consumed | BA numbers, practice locations, specialty for multi-dimensional breakdowns. |
| 7 Intelligence Engine | Consumed | Suggestion events: generated, accepted, dismissed counts and revenue impact for AI Coach metrics. |
| 3 Notification Service | Consumed | Report delivery via email (scheduled reports). |

| Widget | Specification |
| --- | --- |
| Total Revenue (KPI card) | Sum of assessed_fee for paid claims in the selected period. Compared to prior period (delta shown as $ and %). Green/red indicator. |
| Claims Submitted (KPI card) | Count of claims entering submitted state in the period. Prior period comparison. |
| Rejection Rate (KPI card) | rejected / (assessed + rejected + adjusted) as percentage. Prior period comparison. Red if > 10%. |
| Average Fee Per Claim (KPI card) | Total revenue / paid claim count. Prior period comparison. |
| Revenue Trend (line chart) | Monthly revenue over trailing 12 months. Separate lines for AHCIP and WCB if physician bills both pathways. |
| Revenue by BA (bar chart) | For PCPCM dual-BA physicians: side-by-side PCPCM BA vs FFS BA revenue. Single-BA physicians see total only. |
| Top 10 HSC Codes (table) | Most frequently billed HSC codes with count, total revenue, and rejection rate per code. |
| Pending Pipeline (KPI card) | Total value of claims in queued + submitted states. Represents expected future revenue. |

| Widget | Specification |
| --- | --- |
| Rejection Rate Trend (line chart) | Monthly rejection rate over trailing 12 months. Target line at 5% (industry benchmark). |
| Top Rejection Codes (bar chart) | Top 10 explanatory codes (AHCIP) or error codes (WCB) by frequency. Each bar shows count and estimated revenue lost. |
| Rejection by HSC Code (table) | HSC codes with highest rejection rates. Columns: HSC code, description, submitted count, rejected count, rejection %, top rejection reason. |
| Rejection Resolution (funnel) | Rejected → Corrected & Resubmitted → Paid on Resubmission → Written Off. Shows recovery rate. |
| Corrective Action Effectiveness | For claims resubmitted after rejection: success rate on second submission. Broken down by rejection code. |
| Rejection Heatmap | Calendar heatmap showing rejection count by day/week. Highlights submission weeks with high rejection rates. |

| Widget | Specification |
| --- | --- |
| Aging Brackets (stacked bar) | Unresolved claims (not in terminal state) grouped: 0–30 days, 31–60 days, 61–90 days, 90+ days from DOS. Count and value per bracket. |
| Approaching Deadline (table) | Claims within 7 days of submission deadline. Sorted by urgency. Direct link to claim for action. |
| Expired Claims (KPI card) | Claims that expired without submission in the period. Estimated revenue lost. |
| Average Resolution Time (KPI card) | Mean days from claim creation to terminal state (paid, adjusted, written_off). Prior period comparison. |
| Stale Claims (table) | Claims in draft or validated state for >14 days. May represent forgotten or incomplete billing. |

| Widget | Specification |
| --- | --- |
| WCB Claims by Form Type (donut chart) | Distribution of WCB claims across form types (C050E, C151, C568, C050S, C151S, etc.). |
| Timing Tier Distribution (stacked bar) | Claims by timing tier at time of submission. Shows how many claims were submitted at same-day, next-day, 2–5 day, 6–14 day, or 15+ day rates. |
| Fee Tier Analysis (table) | Average fee per timing tier. Estimated revenue gained/lost from timing behaviour. Highlights claims where earlier submission would have earned more. |
| WCB Revenue Trend (line chart) | Monthly WCB revenue alongside AHCIP revenue for comparison. |
| WCB Rejection Rate (KPI card) | WCB-specific rejection rate from return files. |

| Widget | Specification |
| --- | --- |
| Suggestion Acceptance Rate (KPI card) | Accepted / (accepted + dismissed) across all suggestions in the period. |
| Revenue Recovered (KPI card) | Sum of revenue_impact for accepted suggestions. The dollar value the AI Coach added. |
| Suggestions by Category (bar chart) | Count of suggestions generated per category (MODIFIER_ADD, CODE_ALTERNATIVE, etc.). Stacked by status (accepted, dismissed, pending). |
| Top Accepted Suggestions (table) | Most frequently accepted suggestion rules with total revenue impact. |
| Suppressed Rules (table) | Rules currently suppressed for this physician. Option to un-suppress from this view. |

| Widget | Specification |
| --- | --- |
| Revenue by Location (bar chart) | Revenue per practice location for the period. |
| Claims by Location (table) | Claim count, revenue, rejection rate per location. |
| RRNP Impact (KPI card) | Total RRNP premium earned across all qualifying locations. |
| Location Comparison (table) | Side-by-side comparison of two selected locations on key metrics. |

| Period | Default Range | Comparison |
| --- | --- | --- |
| This Week | Monday to today | Same days last week |
| This Month | 1st to today | Same days prior month |
| Last Month | Full prior calendar month | Month before that |
| This Quarter | Q1/Q2/Q3/Q4 start to today | Same quarter prior year |
| This Year | Jan 1 to today | Same period prior year |
| Custom Range | User-selected start and end dates | Same-length period immediately prior |
| Trailing 12 Months | Today minus 12 months | 12 months before that |

| Format | Description |
| --- | --- |
| CSV | Machine-readable. Suitable for import into accounting software (QuickBooks, Sage, Xero). One row per paid claim. |
| PDF Summary | Human-readable. Monthly or annual summary with totals, broken down by BA and location. Suitable for direct submission to accountant. |
| PDF Detailed | Human-readable. Individual claim details with dates, codes, fees. For detailed audit or tax filing. |

| Field | Description |
| --- | --- |
| Period | Month/quarter/year covered by the report |
| Physician Name | Physician's legal name |
| BA Number(s) | All BAs included in the report |
| Total Revenue | Sum of paid claims in the period |
| Revenue by BA | Breakdown per BA (for PCPCM dual-BA) |
| Revenue by Location | Breakdown per practice location |
| AHCIP Revenue | Revenue from AHCIP pathway |
| WCB Revenue | Revenue from WCB pathway |
| Claim Count | Total paid claims |
| RRNP Premium Total | Total RRNP premium earned (if applicable) |
| Adjustments | Claims paid at different amount than submitted (adjusted claims total delta) |
| Written Off | Total value of written-off claims (potential revenue not recovered) |
| GST Note | Physician billing is GST-exempt. Note included for accountant clarity. |

| Report | Frequency | Content |
| --- | --- | --- |
| Weekly Billing Summary | Every Monday | Prior week: claims created, submitted, assessed, rejected. Revenue. Rejection rate. Approaching deadlines. |
| Monthly Performance Report | 1st week of month | Prior month: full revenue breakdown, rejection analysis, AI Coach summary, claim aging status. |
| RRNP Quarterly Summary | After each quarter | RRNP premium earned by location for the quarter. Useful for physicians tracking rural incentive. |
| WCB Timing Report | Weekly (Wed) | WCB claims approaching timing tier downgrades in the next 7 days. Urgency-sorted. |
| Rejection Alert Digest | Daily (if any) | New rejections received in the past 24 hours with rejection codes and corrective guidance. |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| cache_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers |
| metric_key | VARCHAR(50) | No | Metric identifier (e.g., 'revenue_monthly', 'rejection_rate_monthly', 'claims_by_state') |
| period_start | DATE | No | Start of the period this metric covers |
| period_end | DATE | No | End of the period |
| dimensions | JSONB | Yes | Breakdown dimensions: {ba_number, location_id, claim_type, hsc_code}. Null for top-level aggregates. |
| value | JSONB | No | Metric value(s). Structure varies by metric_key. |
| computed_at | TIMESTAMPTZ | No | When this cache entry was last computed |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| report_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers |
| report_type | VARCHAR(50) | No | ACCOUNTANT_SUMMARY, ACCOUNTANT_DETAIL, WEEKLY_SUMMARY, MONTHLY_PERFORMANCE, RRNP_QUARTERLY, WCB_TIMING, REJECTION_DIGEST, DATA_PORTABILITY |
| format | VARCHAR(10) | No | PDF, CSV, ZIP |
| period_start | DATE | Yes | Period covered (null for data portability) |
| period_end | DATE | Yes |  |
| file_path | VARCHAR(255) | No | Path to generated file (encrypted at rest) |
| file_size_bytes | BIGINT | No | File size for download progress indication |
| download_link_expires_at | TIMESTAMPTZ | No | When the download link expires |
| downloaded | BOOLEAN | No | Whether the physician has downloaded this report |
| scheduled | BOOLEAN | No | True if generated by scheduled report. False if on-demand. |
| created_at | TIMESTAMPTZ | No |  |

| Column | Type | Nullable | Description |
| --- | --- | --- | --- |
| subscription_id | UUID | No | Primary key |
| provider_id | UUID FK | No | FK to providers |
| report_type | VARCHAR(50) | No | Which report to generate |
| frequency | VARCHAR(20) | No | DAILY, WEEKLY, MONTHLY, QUARTERLY |
| delivery_method | VARCHAR(20) | No | IN_APP, EMAIL, BOTH. Default: IN_APP. |
| is_active | BOOLEAN | No | Active subscriptions generate reports on schedule |
| created_at | TIMESTAMPTZ | No |  |
| updated_at | TIMESTAMPTZ | No |  |

| ID | Story | Acceptance Criteria |
| --- | --- | --- |
| ANL-001 | As a physician, I want to see my revenue dashboard so I can understand my billing performance | Dashboard loads in < 2 seconds. KPI cards show current period vs prior. Revenue trend chart shows 12 months. Filterable by claim type, BA, location. |
| ANL-002 | As a physician, I want to understand why claims are being rejected | Rejection dashboard shows top codes, rejection rate trend, per-HSC rejection rates. Drill-down to individual rejected claims. |
| ANL-003 | As a physician, I want to see claims approaching their submission deadline | Aging dashboard shows deadline-approaching claims with days remaining. Sorted by urgency. Click to navigate to claim. |
| ANL-004 | As a physician, I want to export a financial summary for my accountant | Select period. Choose format (CSV / PDF Summary / PDF Detailed). Generate and download. CSV includes per-claim detail. |
| ANL-005 | As a physician, I want automatic monthly reports sent to me | Configure report subscription. Monthly PDF generated automatically. Notification with download link. |
| ANL-006 | As a physician, I want to export all my data from Meritum | Data portability export from settings. Generates ZIP with all claims, patients, audit history. Download via secure link. |
| ANL-007 | As a locum physician, I want to compare billing performance across my practice locations | Multi-site dashboard shows per-location revenue, claims, rejection rates. Side-by-side comparison. |
| ANL-008 | As a physician, I want to see how much revenue the AI Coach has recovered for me | AI Coach dashboard shows acceptance rate, total revenue impact of accepted suggestions, suggestions by category. |
| ANL-009 | As a physician who bills WCB, I want to understand my timing tier performance | WCB dashboard shows timing tier distribution, fee impact analysis, claims approaching tier downgrade. |
| ANL-010 | As a delegate, I want to view reports on behalf of my physician | Requires REPORT_VIEW permission. All dashboards and reports scoped to the physician context. REPORT_EXPORT required for downloads. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/analytics/revenue | Revenue dashboard data. Params: period, claim_type, ba_number, location_id. |
| GET | /api/v1/analytics/rejections | Rejection analysis data. Params: period, claim_type, hsc_code. |
| GET | /api/v1/analytics/aging | Claim aging data. Params: claim_type. |
| GET | /api/v1/analytics/wcb | WCB analytics data. Params: period, form_type. |
| GET | /api/v1/analytics/ai-coach | AI Coach performance metrics. Params: period. |
| GET | /api/v1/analytics/multi-site | Multi-site breakdown. Params: period, compare_locations[]. |
| GET | /api/v1/analytics/kpis | All KPI card values for the selected period. Single call for dashboard init. |

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /api/v1/reports/accountant | Generate accountant export. Body: period, format (csv/pdf_summary/pdf_detail). Returns report_id. |
| POST | /api/v1/reports/data-portability | Request full data portability export. Returns report_id. |
| GET | /api/v1/reports/{id} | Check report status and get download link when ready. |
| GET | /api/v1/reports/{id}/download | Download the generated report file. Authenticated, time-limited. |
| GET | /api/v1/reports | List generated reports for the physician. Filterable by type, date range. |

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /api/v1/report-subscriptions | List all active and inactive subscriptions for the physician. |
| POST | /api/v1/report-subscriptions | Create a subscription. Body: report_type, frequency, delivery_method. |
| PUT | /api/v1/report-subscriptions/{id} | Update a subscription (frequency, delivery, active status). |
| DELETE | /api/v1/report-subscriptions/{id} | Cancel a subscription. |

| Report Type | Expected Size | Target Time |
| --- | --- | --- |
| Accountant CSV (monthly) | ~500 rows | < 5 seconds |
| Accountant PDF summary | 2–4 pages | < 10 seconds |
| Accountant PDF detailed (annual) | ~6,000 rows / 50+ pages | < 60 seconds |
| Data portability export | All data (potentially 10+ years) | < 5 minutes |

| Metric | Estimate |
| --- | --- |
| Claims per physician per month | 50–300 (GP), 100–500 (specialist), 500–2,000 (ED/radiologist) |
| Claims per physician lifetime | 5,000–50,000 over 5–10 years |
| Aggregate cache entries per physician | ~500 (12 months × ~40 metric_keys) |
| Generated reports per physician per year | 12 monthly + 52 weekly + on-demand = ~80–100 |

| Action | Details Logged |
| --- | --- |
| DASHBOARD_VIEWED | Dashboard type, period, filters applied. Actor identity. (Rate-limited logging to avoid audit noise.) |
| REPORT_GENERATED | Report type, period, format. Actor identity. |
| REPORT_DOWNLOADED | Report ID, actor identity, timestamp. |
| DATA_PORTABILITY_REQUESTED | Actor identity, timestamp. Sensitive action flagged. |
| DATA_PORTABILITY_DOWNLOADED | Actor identity, timestamp. Sensitive action flagged. |
| REPORT_SUBSCRIPTION_CREATED / UPDATED / CANCELLED | Subscription details, actor identity. |

| # | Question | Context |
| --- | --- | --- |
| 1 | Should anonymised specialty benchmarking be an MVP feature or deferred? | Comparing a physician's rejection rate or revenue per claim to their specialty average could be valuable but requires sufficient user base and privacy framework. |
| 2 | Should the accountant export support direct delivery to accountant email? | Would require the physician to configure accountant email and consent to external delivery of PHI-containing reports. MVP: physician downloads and forwards. |
| 3 | What retention period is appropriate for generated reports? | Current spec: 90 days (scheduled), 30 days (on-demand), 72 hours (data portability). May need to align with HIA retention requirements. |
| 4 | Should analytics support year-over-year comparison on the same chart? | Useful for identifying seasonal trends but adds UI complexity. MVP: prior-period comparison only. |
| 5 | What is the right cache refresh strategy for physicians with very high claim volumes (radiologists)? | Nightly batch may be insufficient for 2,000+ claims/month. May need more frequent incremental updates. |

| Item | Value |
| --- | --- |
| Parent document | Meritum PRD v1.3 |
| Domain | Analytics & Reporting (Domain 8 of 13) |
| Build sequence position | 8th |
| Dependencies | Domain 1 (IAM), Domain 2 (Reference Data), Domain 4 (Claim Lifecycle), Domain 5 (Provider Mgmt), Domain 7 (Intelligence Engine) |
| Consumed by | Domain 3 (Notification Service for scheduled report delivery) |
| Version | 1.0 |
| Date | February 2026 |
| Next domain in critical path | Domain 9 (Notification Service) |

