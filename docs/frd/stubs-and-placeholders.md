# Stubs, Placeholders & Hardcoded Values — Codebase Audit

> **Date:** 2026-02-24
> **Scope:** Full codebase scan of `meritum/` monorepo (apps/api, apps/web, packages/shared, scripts/)
> **Excludes:** node_modules, .git, .next, test files (unless test-only stubs are noted)

---

## 1. Stub Implementations (Functions Returning Dummy Data)

### 1.1 Data Portability Export Service — 6 CSV Generator Stubs

**File:** `apps/api/src/domains/platform/export.service.ts`
**Severity:** HIGH — These functions are called by `generateFullPortabilityExport()` (line 106) which assembles a ZIP. Physicians downloading their data export will receive empty CSVs (headers only).

| Lines | Function | Returns | Blocked By |
|-------|----------|---------|------------|
| 17–23 | `generateClaimsCsv()` | `'claim_id,service_date,health_service_code,amount,status\n'` | Claims domain integration |
| 29–35 | `exportWcbClaimsCsv()` | `'claim_id,service_date,form_type,status,amount\n'` | WCB domain integration |
| 41–47 | `generatePatientsCsv()` | `'patient_id,first_name,last_name,date_of_birth,phn\n'` | Patients domain integration |
| 53–59 | `exportAssessmentsCsv()` | `'assessment_id,patient_id,assessment_date,type,status\n'` | Assessments domain integration |
| 65–71 | `exportAnalyticsCsv()` | `'metric,period,value,unit\n'` | Analytics domain integration |
| 77–83 | `exportIntelligenceCsv()` | `'insight_id,generated_at,category,recommendation,confidence\n'` | Intelligence domain integration |

**Action Required:** Each function needs to query its respective domain's repository layer and stream real data. The ZIP orchestration (lines 106–153) is already wired up correctly.

---

### 1.2 Reference Service — Placeholder Functions Awaiting Domain 4

**File:** `apps/api/src/domains/reference/reference.service.ts`
**Severity:** MEDIUM — Functions return valid but incomplete data. No runtime errors, but physicians receive generic results instead of personalised ones.

| Lines | Function | Placeholder Behaviour |
|-------|----------|-----------------------|
| 187–214 | `getHscFavourites()` | Returns top-N codes from active SOMB version instead of physician's actual billing history. Comment (line 190–193): *"Since the claim history tables don't exist yet (Domain 4), this function returns the top-N codes from the active SOMB version as a placeholder."* |
| 1145–1204 | `getPhysicianImpact()` | Returns empty arrays for `deprecated_codes_used` and `fee_changes` (lines 1183–1184). Comment (line 1150): *"Since Domain 4 (Claims) doesn't exist yet, this returns placeholder data."* Only `new_relevant_codes` is populated from version data. |

**Action Required:** Wire these functions to claim history tables once Domain 4.0 is integrated. The `_userId` parameter (line 1157) is already accepted but unused (prefixed with underscore).

---

### 1.3 Intelligence Engine — Fee Difference Placeholder

**File:** `apps/api/src/domains/intel/intel.service.ts`
**Severity:** LOW — Affects AI Coach suggestion display only.

| Line | Context | Placeholder |
|------|---------|-------------|
| 727 | `interpolate()` function, `{{fee_difference}}` template token | Returns hardcoded `'0.00'` — comment: *"Placeholder — calculated when revenue_impact_formula is evaluated"* |

**Action Required:** Implement fee difference calculation using the claim's current fee vs. suggested alternative fee from the SOMB reference data.

---

## 2. Phase 2 Placeholders (501 Not Implemented)

### 2.1 Mobile Offline Sync Endpoint

**File:** `apps/api/src/domains/mobile/routes/mobile.routes.ts`
**Severity:** LOW — Intentional deferral. Documented in route comments. Tests exist.

| Lines | Endpoint | Response |
|-------|----------|----------|
| 187–203 | `POST /api/v1/sync/claims` | HTTP 501 with body `{ message: 'Offline sync is not available in this version', phase: 2 }` |

**Note:** No authentication required (by design — client may call without valid session when reconnecting after offline period). Test coverage in `mobile.routes.test.ts` lines 846–895 verifies 501 in all scenarios.

**Action Required:** Implement in Phase 2 when offline-first mobile support is scoped.

---

## 3. Placeholder Values in Business Logic

### 3.1 Delegate Invitation — Temporary User ID

**File:** `apps/api/src/domains/provider/provider.service.ts`
**Severity:** MEDIUM — Uses `actorId` as placeholder for `delegateUserId` until invitation acceptance.

| Lines | Context |
|-------|---------|
| 1573–1584 | `delegateUserId: actorId` — Comment (line 1574): *"delegateUserId is a placeholder — will be resolved on acceptance. We use a deterministic UUID derived from the email to satisfy the FK constraint, but the actual resolution happens on acceptance via Domain 1."* |

**Action Required:** Verify that the acceptance flow (Domain 1) correctly overwrites this placeholder with the actual delegate user's ID. If the invitation expires without acceptance, ensure cleanup handles the placeholder FK correctly.

---

## 4. Hardcoded Configuration Values

### 4.1 Default Database Credentials

**File:** `apps/api/drizzle.config.ts`
**Severity:** HIGH — Contains default development credentials in source code.

| Line | Value |
|------|-------|
| 8 | `url: process.env.DATABASE_URL ?? 'postgresql://meritum:meritum@localhost:5432/meritum'` |

**Action Required:** The fallback string contains username `meritum` and password `meritum`. While this only applies when `DATABASE_URL` is unset (development), consider removing the fallback entirely and requiring the env var, or at minimum ensure `.env.example` documents this.

---

### 4.2 Default Stripe Price IDs

**File:** `apps/api/src/lib/env.ts`
**Severity:** HIGH — Placeholder Stripe price IDs will fail at Stripe API call time.

| Line | Variable | Default Value |
|------|----------|---------------|
| 19 | `STRIPE_PRICE_CLINIC_MONTHLY` | `'price_clinic_monthly_default'` |
| 20 | `STRIPE_PRICE_CLINIC_ANNUAL` | `'price_clinic_annual_default'` |

**Action Required:** These defaults are non-functional. Any subscription creation attempt without real env vars will pass Zod validation but fail at Stripe. Consider making these required (no default) or adding runtime validation before Stripe API calls.

---

### 4.3 CORS Origin and Port Defaults

**Files:** `apps/api/src/lib/env.ts`, `apps/api/src/server.ts`
**Severity:** LOW — Standard development defaults. Appropriate for local development.

| File | Line | Value | Purpose |
|------|------|-------|---------|
| `env.ts` | 15 | `API_PORT: z.coerce.number().default(3001)` | API server port |
| `env.ts` | 17 | `CORS_ORIGIN: z.string().default('http://localhost:3000')` | CORS allow origin |
| `server.ts` | 18 | `process.env.CORS_ORIGIN ?? 'http://localhost:3000'` | Duplicate fallback |
| `server.ts` | 34 | `process.env.API_PORT ?? '3001'` | Duplicate fallback |

**Note:** `server.ts` duplicates the env.ts defaults, creating two places to maintain. Consider using `getEnv()` in `server.ts` instead of raw `process.env` access.

---

### 4.4 Hardcoded Token Expiry Durations

**File:** `apps/api/src/domains/iam/iam.service.ts`
**Severity:** LOW — Values align with CLAUDE.md spec. Constants are named but not configurable via environment.

| Line | Constant | Value | Spec Reference |
|------|----------|-------|----------------|
| 37 | `TOKEN_EXPIRY_MS` | `24 * 60 * 60 * 1000` (24h) | Session duration: 24h |
| 591 | `MFA_SESSION_TOKEN_EXPIRY_MS` | `5 * 60 * 1000` (5min) | MFA verification window |
| 1266 | `PASSWORD_RESET_TOKEN_EXPIRY_MS` | `60 * 60 * 1000` (1h) | Password reset link lifetime |
| 1406 | `INVITATION_TOKEN_EXPIRY_MS` | `72 * 60 * 60 * 1000` (72h) | Delegate invitation lifetime |

**File:** `apps/api/src/domains/iam/iam.handlers.ts`

| Line | Constant | Value |
|------|----------|-------|
| 63 | `SESSION_COOKIE_MAX_AGE` | `86400` (24h in seconds) |

**Action Required:** Consider moving these to a central `config/auth.ts` or making them environment-configurable for operational flexibility (e.g., shorter session durations in sensitive environments).

---

### 4.5 Rate Limit Defaults

**Files:** `apps/api/src/server.ts`, `apps/api/src/plugins/rate-limit.plugin.ts`
**Severity:** LOW — Values match CLAUDE.md spec exactly.

| File | Line | Value | Spec |
|------|------|-------|------|
| `server.ts` | 21 | `max: 100` | Default: 100 req/min per user |
| `rate-limit.plugin.ts` | 47 | `max: 10` | Auth endpoints: 10 req/min per IP |
| `rate-limit.plugin.ts` | 59 | `max: 5` | File uploads: 5 req/min per user |

**Action Required:** Consider making these environment-configurable for production tuning without redeployment.

---

### 4.6 Cache and Timeout Constants

**Severity:** LOW — Operational constants that may need tuning.

| File | Line | Constant | Value |
|------|------|----------|-------|
| `domains/analytics/services/cache-refresh.service.ts` | 14 | `DEFAULT_STALE_THRESHOLD_MINUTES` | `60` |
| `domains/analytics/services/dashboard.service.ts` | 27 | `CACHE_STALE_THRESHOLD_MINUTES` | `60` |
| `domains/patient/patient.service.ts` | 1321 | CSV import job expiry | `60 * 60 * 1000` (1h) |
| `domains/wcb/wcb.service.ts` | 3413 | `DOWNLOAD_EXPIRY_SECONDS` | `3600` (1h) |
| `domains/support/services/help-centre.service.ts` | 80 | `RATE_LIMIT_WINDOW_MS` | `60_000` (1min) |
| `packages/shared/src/constants/intelligence.constants.ts` | 217 | `LLM_TIMEOUT_MS` | `3000` (3s) |
| `domains/platform/platform.service.ts` | 428 | Subscription period calculation | `30 * 24 * 60 * 60 * 1000` (30d) |

---

### 4.7 Magic Numbers — Large Batch Limits

**File:** `apps/api/src/domains/reference/reference.service.ts`
**Severity:** MEDIUM — Silently caps result sets. Could cause data loss in physician impact analysis.

| Line | Context | Value |
|------|---------|-------|
| 1190 | `listHscByVersion()` in `getPhysicianImpact()` | `limit: 100000` |
| 1107 | HSC code listing | `limit: 100000` |
| 1747 | WCB code search | `limit: 100000` |

**File:** `apps/api/src/domains/claim/claim.service.ts`

| Line | Context | Value |
|------|---------|-------|
| 2527 | Export batch size | `pageSize: 10000` |

**Action Required:** Extract to named constants. Consider whether these limits are sufficient for the data volume and whether pagination would be more appropriate.

---

### 4.8 Website Hardcoded Configuration

**File:** `meritum-website/src/config/site.ts`
**Severity:** LOW — Marketing site, not the application.

| Line | Value |
|------|-------|
| 4 | `url: 'https://meritum.ca'` |
| 5 | `email: 'hello@meritum.ca'` |
| 7 | `linkedin: 'https://linkedin.com/company/meritum-health'` |
| 8 | `ctaUrl: 'https://app.meritum.ca/signup'` |

**File:** `meritum-website/src/config/pricing.ts`

| Lines | Value | Detail |
|-------|-------|--------|
| 4–8 | Early Bird pricing | 100 spots, $199/month, $2388/year, 12-month lock |
| 11–13 | Standard pricing | $279/month, $3181/year |
| 22 | Currency | `'CAD'` |
| 23 | GST | `5` (percent) |

---

## 5. Type Safety Issues (`as any` Assertions)

**Severity:** MEDIUM — 166 instances of `as any` in production code (excluding test files). 946 total including tests.

### 5.1 Recurring Pattern: Delegate Context Access

The most common `as any` pattern is accessing `delegateContext` from `AuthContext`:

```typescript
if (ctx.role?.toUpperCase() === 'DELEGATE' && (ctx as any).delegateContext) {
  return (ctx as any).delegateContext.physicianProviderId;
}
```

**Files affected (identical pattern):**
- `domains/ahcip/ahcip.handlers.ts:37–38`
- `domains/claim/claim.handlers.ts:63–64`
- `domains/analytics/routes/dashboard.routes.ts:46–47`
- `domains/analytics/routes/report.routes.ts:49–50`
- `domains/analytics/routes/subscription.routes.ts:38–39`

**Root Cause:** The `AuthContext` type definition likely doesn't include `delegateContext` as a required field, forcing handlers to cast.

**Action Required:** Update the `AuthContext` type to include `delegateContext` as an optional typed field, eliminating all 10+ `as any` casts for this pattern.

### 5.2 Repository Update Calls

Multiple `as any` casts when passing partial update objects to repository functions:

- `domains/ahcip/ahcip.service.ts:617, 1260, 1771, 1786, 1924, 2048, 2428` (7 instances)
- `domains/claim/claim.handlers.ts:173, 192`

**Root Cause:** Drizzle update type signatures require exact column types. Partial update objects don't satisfy the full type.

**Action Required:** Define proper `Partial<>` update types in the shared schema package, or create typed update input types per domain.

---

## 6. "Not Available" Guard Clauses (Dependency Checks)

**Severity:** INFO — These are defensive checks for optional dependencies, not stubs. Listed for completeness.

| File | Line | Guard |
|------|------|-------|
| `domains/platform/practice-stripe.service.ts` | 52 | `'Stripe subscriptions.create is not available'` |
| `domains/platform/practice-stripe.service.ts` | 96 | `'Stripe subscriptions API is not available'` |
| `domains/platform/practice-stripe.service.ts` | 124 | `'Stripe subscriptions API is not available'` |
| `domains/wcb/wcb.service.ts` | 3273 | `'XSD validation not available: validator not configured'` |
| `domains/wcb/wcb.service.ts` | 3277 | `'XSD validation not available: file storage not configured'` |
| `domains/wcb/wcb.service.ts` | 3391 | `'Download URL generation not available: generator not configured'` |
| `domains/provider/provider.service.ts` | 1309 | `'WCB matrix lookup is not available'` |

**Note:** These are intentional runtime guards for services that require external dependencies (Stripe SDK, XSD validator, S3-compatible storage). They throw descriptive errors rather than silently failing. No action required unless the dependency should always be present.

---

## 7. Summary by Priority

| Priority | Category | Count | Action |
|----------|----------|-------|--------|
| **HIGH** | Export service CSV stubs | 6 functions | Wire to domain repositories |
| **HIGH** | Placeholder Stripe price IDs | 2 env defaults | Make required or add runtime validation |
| **HIGH** | Default DB credentials in source | 1 file | Remove fallback or document |
| **MEDIUM** | Reference service placeholders | 2 functions | Wire to claim history (Domain 4) |
| **MEDIUM** | Delegate invitation placeholder ID | 1 location | Verify acceptance flow handles correctly |
| **MEDIUM** | `as any` type assertions | 166 production instances | Fix AuthContext type + Drizzle update types |
| **MEDIUM** | Magic number batch limits | 4 locations | Extract to named constants |
| **LOW** | Phase 2 sync endpoint (501) | 1 endpoint | Implement in Phase 2 |
| **LOW** | Fee difference placeholder | 1 template token | Implement calculation |
| **LOW** | Token expiry constants | 5 constants | Consider making env-configurable |
| **LOW** | Rate limit constants | 3 values | Consider making env-configurable |
| **LOW** | Cache/timeout constants | 7 values | Consider making env-configurable |
| **LOW** | CORS/port duplicate defaults | 2 locations | Use `getEnv()` in server.ts |
| **INFO** | Dependency guard clauses | 7 locations | No action needed |
