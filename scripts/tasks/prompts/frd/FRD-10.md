# Task FRD-10: Update Domain 8 (Analytics & Reporting) FRD

## Objective

Read the current Domain 8 FRD and the actual implementation, then update the FRD in-place. The implementation uses a subdirectory structure (repos/, routes/, services/) rather than the standard 5-file pattern. Fold in ARP analytics, reciprocal billing reporting, and subscription-based report generation.

## Step 1: Read Current FRD

Read the full file:
- `docs/frd/extracted/Meritum_Domain_08_Analytics_Reporting.md`

## Step 2: Read Implementation

**Domain module (subdirectory structure):**

Repositories:
- `apps/api/src/domains/analytics/repos/analytics-cache.repo.ts`
- `apps/api/src/domains/analytics/repos/dashboard-query.repo.ts`
- `apps/api/src/domains/analytics/repos/generated-reports.repo.ts`
- `apps/api/src/domains/analytics/repos/report-subscriptions.repo.ts`

Routes:
- `apps/api/src/domains/analytics/routes/dashboard.routes.ts`
- `apps/api/src/domains/analytics/routes/report.routes.ts`
- `apps/api/src/domains/analytics/routes/subscription.routes.ts`

Services:
- `apps/api/src/domains/analytics/services/cache-refresh.service.ts`
- `apps/api/src/domains/analytics/services/dashboard.service.ts`
- `apps/api/src/domains/analytics/services/download.service.ts`
- `apps/api/src/domains/analytics/services/report-generation.service.ts`
- `apps/api/src/domains/analytics/services/scheduled-reports.service.ts`

**Shared schemas and constants:**
- `packages/shared/src/constants/analytics.constants.ts`

**Validation schemas (if exist):**
- `packages/shared/src/schemas/validation/analytics.schema.ts` (check this path)

## Step 3: Read Supplementary Specs

**MVP Features Addendum:**
- `docs/frd/extracted/Meritum_MVP_Features_Addendum.md`
  - B5: ARP/APP Shadow Billing — ARP-specific analytics dashboard section, shadow billing volumes/revenue
  - B8: Reciprocal Billing — reciprocal billing reporting (out-of-province claim volumes, success rates)
  - TM summary report reference

## Step 4: Key Changes to Incorporate

1. **Subdirectory architecture** — The implementation uses repos/, routes/, services/ subdirectories rather than the standard 5-file flat pattern. Document this structural difference.

2. **Caching layer** — `analytics-cache.repo.ts` and `cache-refresh.service.ts` implement a caching strategy for expensive dashboard queries. Document the cache invalidation strategy, TTLs, and refresh mechanism.

3. **Report subscriptions** — `report-subscriptions.repo.ts` and `subscription.routes.ts` implement subscription-based report delivery. Physicians can subscribe to scheduled reports (weekly/monthly) with delivery preferences.

4. **Scheduled reports** — `scheduled-reports.service.ts` handles automated report generation and delivery on configured schedules.

5. **Download service** — `download.service.ts` handles report file generation and presigned URL creation for secure downloads.

6. **Dashboard queries** — `dashboard-query.repo.ts` contains the SQL queries for dashboard metrics. Check what metrics are implemented vs. what the FRD specifies.

7. **ARP analytics** — If implemented: dedicated dashboard section for ARP/shadow billing volumes, revenue tracking, and comparison against FFS billing.

8. **Reciprocal billing reporting** — If implemented: out-of-province claim tracking, success rates by province, revenue from reciprocal patients.

9. **Report types** — Check `analytics.constants.ts` for the full set of report types, metric definitions, filter options, and aging brackets.

10. **Accountant export** — Verify the FRD documents the accountant export package (revenue summary + claim detail + GST report as ZIP).

## Step 5: Write Updated FRD

Write the complete updated FRD to: `docs/frd/extracted/Meritum_Domain_08_Analytics_Reporting.md`

### Format Rules

- Preserve existing section structure and formal writing style
- Note the subdirectory module structure as a deviation from the standard pattern
- Add sections for caching layer, report subscriptions, scheduled reports
- Add ARP analytics and reciprocal billing reporting sections if implemented
- Update data model with all implemented tables
- Update API contracts with all implemented endpoints
- Do not add TODO/TBD/placeholder content

When complete, output on its own line: [TASK_COMPLETE]
If blocked, output: [TASK_BLOCKED] reason: <explanation>
