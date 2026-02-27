# Task Breakdown — FRD Extensions (CC-001, MVPADD-001, MOB-002)

> **Generated:** 2026-02-25
> **Scope:** 3 FRDs, ~25 gaps (A1–A7, B1–B12, C1–C5), 16 new tables, 6 modified tables, ~50 new API endpoints
> **Baseline:** All 14 domains fully implemented (326K LOC). All tasks are extensions.

---

## Build Order Rationale

Dependencies flow downward. Each phase depends on all prior phases.

```
Phase 1  Schema Foundation ──────────────────────────────── (all 3 FRDs)
Phase 2  Reference Data Extensions ──────────────────────── (B1, B6, B7, B8, B9, B11, B12, A3)
Phase 3  Patient Registry Extensions ────────────────────── (B2, B8)
Phase 4  Provider Management Extensions ─────────────────── (B5, B10, C5)
Phase 5  Claim Lifecycle Extensions ─────────────────────── (A6, B3, B7, B9, B11)
Phase 6  Connect Care SCC Parser ────────────────────────── (A1, A4, A5)
Phase 7  Connect Care Import Workflow ───────────────────── (A2)
Phase 8  Intelligence Engine Extensions ─────────────────── (B4, B4a)
Phase 9  Mobile Companion v2 ────────────────────────────── (C1, C2, C3, C5)
Phase 10 Reconciliation ─────────────────────────────────── (C4)
Phase 11 Security Tests ─────────────────────────────────── (all new endpoints)
```

---

## Phase 1: Schema Foundation

All new/modified Drizzle table schemas, Zod validation schemas, constants, types, and migration generation. Must be completed first — every subsequent phase depends on these definitions.

### Task 1.01 — SCC Constants
**File:** `packages/shared/src/constants/scc.constants.ts` (NEW)
**Action:** Create. Define `SCC_SPEC_VERSIONS`, `CURRENT_SCC_SPEC_VERSION`, `SCC_EXTRACT_TYPES`, `SCC_CHARGE_STATUSES`, `SCC_VALIDATION_SEVERITIES`, `IMPORT_SOURCES`, `ICD_MATCH_QUALITIES`.
**FRD ref:** CC-001 §3.8, §8
**Depends on:** nothing

### Task 1.02 — Extend Claim Constants
**File:** `packages/shared/src/constants/claim.constants.ts` (MODIFY)
**Action:** Add `IMPORT_SOURCES` enum (`MANUAL`, `CONNECT_CARE_CSV`, `CONNECT_CARE_SFTP`, `EMR_GENERIC`), `JUSTIFICATION_SCENARIOS` enum (5 values), `BUNDLING_RELATIONSHIPS` enum (`BUNDLED`, `INDEPENDENT`, `INTRINSICALLY_LINKED`).
**FRD ref:** CC-001 §8, MVPADD-001 §4.3, §4.4

### Task 1.03 — Extend Provider Constants
**File:** `packages/shared/src/constants/provider.constants.ts` (MODIFY)
**Action:** Add `BA_SUBTYPES` enum (`ANNUALISED`, `SESSIONAL`, `BCM`), `ROUTING_REASONS` enum. Extend `BA_TYPES` to include `ARP`.
**FRD ref:** MVPADD-001 §6.1

### Task 1.04 — Extend Mobile Constants
**File:** `packages/shared/src/constants/mobile.constants.ts` (MODIFY)
**Action:** Add `SHIFT_SOURCES` enum (`MANUAL`, `INFERRED`), `PHN_CAPTURE_METHODS` enum (`BARCODE_SCAN`, `PATIENT_SEARCH`, `MANUAL_ENTRY`, `LAST_4`), `RECONCILIATION_MATCH_CATEGORIES`, shift reminder constants.
**FRD ref:** MOB-002 §3, §4, §5

### Task 1.05 — Extend Intelligence Constants
**File:** `packages/shared/src/constants/intelligence.constants.ts` (MODIFY)
**Action:** Add `CONFIDENCE_TIERS` enum (`TIER_A`, `TIER_B`, `TIER_C`, `SUPPRESS`), `BEDSIDE_CONTINGENT_SIGNALS`.
**FRD ref:** MVPADD-001 §5.2

### Task 1.06 — ICD Crosswalk Drizzle Schema
**File:** `packages/shared/src/schemas/db/reference.schema.ts` (MODIFY)
**Action:** Add `icdCrosswalk` table definition (10 columns). Add indexes on `icd10_code`, `icd9_code`. Add unique constraint on `(icd10_code, icd9_code)`.
**FRD ref:** CC-001 §5.2, §10.1

### Task 1.07 — Provider Registry Drizzle Schema
**File:** `packages/shared/src/schemas/db/reference.schema.ts` (MODIFY)
**Action:** Add `providerRegistry` table (12 columns) with trigram index on `last_name`, unique on `practitioner_id`. Add `billingGuidance` table (16 columns). Add `provincialPhnFormats` table (14 columns). Add `reciprocalBillingRules` table (9 columns).
**FRD ref:** MVPADD-001 §2.1.1, §2.2.1, §3.2.1, §3.2.2

### Task 1.08 — Anesthesia & Bundling & Justification Drizzle Schemas
**File:** `packages/shared/src/schemas/db/reference.schema.ts` (MODIFY)
**Action:** Add `anesthesiaRules` table (12 columns). Add `bundlingRules` table (14 columns) with unique constraint `code_a < code_b`. Add `justificationTemplates` table (10 columns).
**FRD ref:** MVPADD-001 §4.2.1, §4.3.1, §4.4.2

### Task 1.09 — Import Batches Drizzle Schema
**File:** `packages/shared/src/schemas/db/claim.schema.ts` (MODIFY)
**Action:** Add `importBatches` table (18 columns). Add 7 new columns to `claims` table: `import_source`, `import_batch_id`, `raw_file_reference`, `scc_charge_status`, `icd_conversion_flag`, `icd10_source_code`, `shift_id`.
**FRD ref:** CC-001 §8, §10

### Task 1.10 — Claim Templates & Justifications Drizzle Schema
**File:** `packages/shared/src/schemas/db/claim.schema.ts` (MODIFY)
**Action:** Add `claimTemplates` table (14 columns). Add `claimJustifications` table (11 columns). Add `recentReferrers` table (7 columns).
**FRD ref:** MVPADD-001 §4.1.2, §4.4.3, §2.1.2

### Task 1.11 — Eligibility Cache Drizzle Schema
**File:** `packages/shared/src/schemas/db/patient.schema.ts` (MODIFY)
**Action:** Add `eligibilityCache` table (9 columns) with index on `(patient_phn_hash, date_of_service)`.
**FRD ref:** MVPADD-001 §3.1.3

### Task 1.12 — Provider Management Schema Extensions
**File:** `packages/shared/src/schemas/db/provider.schema.ts` (MODIFY)
**Action:** Add `ba_subtype` column to `businessArrangements`. Add `baFacilityMappings` table (7 columns) with unique `(provider_id, location_id)`. Add `baScheduleMappings` table (9 columns). Add `is_connect_care_user` and `connect_care_enabled_at` columns to `providers`.
**FRD ref:** MVPADD-001 §6.1.1, §6.2.1, §6.2.2; MOB-002 §6.1

### Task 1.13 — Intelligence Schema Extensions
**File:** `packages/shared/src/schemas/db/intelligence.schema.ts` (MODIFY)
**Action:** Add `is_bedside_contingent` and `confidence_tier_overrides` columns to `aiRules`. Add `auto_applied_count`, `pre_applied_count`, `pre_applied_removed_count` columns to `aiProviderLearning`.
**FRD ref:** MVPADD-001 §5.2.3

### Task 1.14 — Shift Schedules Drizzle Schema
**File:** `packages/shared/src/schemas/db/mobile.schema.ts` (MODIFY)
**Action:** Add `shiftSchedules` table (12 columns). Revise `edShiftEncounters` table (add `phn_capture_method`, `phn_is_partial`, `matched_claim_id`, `free_text_tag`; ensure `patient_phn` column). Add `schedule_id`, `shift_source`, `inferred_confirmed` columns to `edShifts`.
**FRD ref:** MOB-002 §7

### Task 1.15 — SCC Extract Zod Schemas
**File:** `packages/shared/src/schemas/scc-extract.schema.ts` (NEW)
**Action:** Create. Define `sccAhcipRowSchema` (21 fields), `sccWcbRowSchema` (13 fields), `parseResultSchema`, `parsedRowSchema`, `importBatchSchema`, `importConfirmSchema`.
**FRD ref:** CC-001 §3.5, §3.7

### Task 1.16 — Reference Data Zod Schemas (New Endpoints)
**File:** `packages/shared/src/schemas/reference.schema.ts` (MODIFY)
**Action:** Add Zod schemas for: ICD crosswalk lookup, provider registry search, billing guidance CRUD, anesthesia calculation request/response, bundling check request/response, justification template, provincial PHN format, reciprocal billing rules.
**FRD ref:** MVPADD-001 §2.1.4, §2.2.4, §3.2.5, §4.2.4, §4.3.3, §4.4.5; CC-001 §11.3

### Task 1.17 — Claim Extension Zod Schemas
**File:** `packages/shared/src/schemas/claim.schema.ts` (MODIFY)
**Action:** Add Zod schemas for: import upload response, import confirm request, import history query, claim template CRUD, claim justification CRUD, recent referrers, routing resolve request/response.
**FRD ref:** CC-001 §11.1–11.2; MVPADD-001 §4.1.4, §4.4.5, §2.1.4

### Task 1.18 — Patient Extension Zod Schemas
**File:** `packages/shared/src/schemas/patient.schema.ts` (MODIFY)
**Action:** Add Zod schemas for: eligibility check request/response, eligibility override, bulk eligibility check, province detection request/response.
**FRD ref:** MVPADD-001 §3.1.5, §3.2.5

### Task 1.19 — Mobile Extension Zod Schemas
**File:** `packages/shared/src/schemas/validation/mobile.validation.ts` (MODIFY)
**Action:** Add Zod schemas for: shift schedule CRUD, shift start/end, encounter logging, reconciliation trigger/confirm/resolve, RRULE validation.
**FRD ref:** MOB-002 §8

### Task 1.20 — Province Detection Utility
**File:** `packages/shared/src/utils/province-detect.ts` (NEW)
**Action:** Create. Implement `detectProvince(healthNumber: string): ProvinceDetectionResult` with format matching against all 11 provinces/territories. Quebec detection triggers private billing redirect.
**FRD ref:** MVPADD-001 §3.2.4

### Task 1.21 — Update Barrel Exports
**Files:** `packages/shared/src/schemas/index.ts`, `packages/shared/src/constants/index.ts` (MODIFY both)
**Action:** Add exports for all new schemas and constants created in Tasks 1.01–1.20.

### Task 1.22 — Generate Migration
**Action:** Run `drizzle-kit generate` to produce migration file from all schema changes. Store in `apps/api/drizzle/migrations/`.
**Depends on:** Tasks 1.06–1.14

---

## Phase 2: Reference Data Extensions (Domain 2)

Repository, service, handler, and route additions to the reference domain for new lookup tables and APIs.

### Task 2.01 — ICD Crosswalk Repository
**File:** `apps/api/src/domains/reference/reference.repository.ts` (MODIFY)
**Action:** Add functions: `getIcdCrosswalkByIcd10(icd10Code)`, `searchIcdCrosswalk(query, pagination)`, `bulkInsertIcdCrosswalk(rows)`.
**FRD ref:** CC-001 §5.4

### Task 2.02 — Provider Registry Repository
**File:** `apps/api/src/domains/reference/reference.repository.ts` (MODIFY)
**Action:** Add functions: `searchProviderRegistry(query, filters, pagination)`, `getProviderByPractitionerId(id)`, `bulkUpsertProviderRegistry(rows)`, `getProviderRegistryLastRefreshed()`.
**FRD ref:** MVPADD-001 §2.1

### Task 2.03 — Billing Guidance Repository
**File:** `apps/api/src/domains/reference/reference.repository.ts` (MODIFY)
**Action:** Add functions: `listBillingGuidance(filters, pagination)`, `searchBillingGuidance(query)`, `getGuidanceForCode(sombCode)`, `trackGuidanceView(guidanceId, providerId, action)`.
**FRD ref:** MVPADD-001 §2.2

### Task 2.04 — Provincial PHN Formats & Reciprocal Rules Repository
**File:** `apps/api/src/domains/reference/reference.repository.ts` (MODIFY)
**Action:** Add functions: `listProvincialPhnFormats()`, `getReciprocalRules(provinceCode, sombCode?)`.
**FRD ref:** MVPADD-001 §3.2

### Task 2.05 — Anesthesia Rules Repository
**File:** `apps/api/src/domains/reference/reference.repository.ts` (MODIFY)
**Action:** Add functions: `listAnesthesiaRules()`, `getAnesthesiaRulesByType(ruleType)`.
**FRD ref:** MVPADD-001 §4.2

### Task 2.06 — Bundling Rules Repository
**File:** `apps/api/src/domains/reference/reference.repository.ts` (MODIFY)
**Action:** Add functions: `getBundlingRuleForPair(codeA, codeB)`, `listBundlingRules(filters)`, `checkBundlingConflicts(codes[])`.
**FRD ref:** MVPADD-001 §4.3

### Task 2.07 — Justification Templates Repository
**File:** `apps/api/src/domains/reference/reference.repository.ts` (MODIFY)
**Action:** Add functions: `listJustificationTemplates(scenario?)`, `getJustificationTemplate(id)`.
**FRD ref:** MVPADD-001 §4.4

### Task 2.08 — Reference Service Extensions
**File:** `apps/api/src/domains/reference/reference.service.ts` (MODIFY)
**Action:** Add service functions wrapping repository calls for: ICD crosswalk lookup, provider registry search, billing guidance retrieval/search/tracking, provincial formats listing, reciprocal rules lookup, anesthesia rules listing, bundling rules lookup, justification templates listing. Each applies business logic (e.g., active-only filtering, sort ordering for crosswalk candidates).
**FRD ref:** All reference data endpoints across CC-001 and MVPADD-001

### Task 2.09 — Reference Handlers — ICD Crosswalk
**File:** `apps/api/src/domains/reference/reference.handlers.ts` (MODIFY)
**Action:** Add handlers: `getIcdCrosswalk`, `searchIcdCrosswalk`.
**FRD ref:** CC-001 §11.3

### Task 2.10 — Reference Handlers — Provider Registry, Guidance, Provincial, Bundling, Anesthesia, Justification
**File:** `apps/api/src/domains/reference/reference.handlers.ts` (MODIFY)
**Action:** Add handlers for all new reference endpoints (provider search, provider by ID, guidance list/search/code/track, provincial formats, reciprocal rules, anesthesia rules, bundling rules/pair, justification templates).
**FRD ref:** MVPADD-001 §2.1.4, §2.2.4, §3.2.5, §4.2.4, §4.3.3, §4.4.5

### Task 2.11 — Reference Routes — New Endpoints
**File:** `apps/api/src/domains/reference/reference.routes.ts` (MODIFY)
**Action:** Register all new reference routes with Zod schema validation and permission guards:
- `GET /api/v1/reference/icd-crosswalk/{icd10Code}`
- `GET /api/v1/reference/icd-crosswalk`
- `GET /api/v1/reference/providers/search`
- `GET /api/v1/reference/providers/{practitionerId}`
- `GET /api/v1/reference/guidance`, `/guidance/search`, `/guidance/code/{sombCode}`
- `POST /api/v1/reference/guidance/{id}/track`
- `GET /api/v1/reference/provincial-phn-formats`
- `GET /api/v1/reference/reciprocal-rules/{provinceCode}`
- `GET /api/v1/reference/anesthesia-rules`
- `GET /api/v1/reference/bundling-rules`, `/bundling-rules/pair/{codeA}/{codeB}`
- `GET /api/v1/reference/justification-templates`, `/justification-templates/{id}`

### Task 2.12 — Reference Data Seed — ICD Crosswalk
**File:** `apps/api/src/domains/reference/seeds/icd-crosswalk.seed.ts` (NEW)
**Action:** Create seed script for initial ICD-10-CA to ICD-9 crosswalk data. At minimum, top 100 most common conversions.
**FRD ref:** CC-001 §5.2

### Task 2.13 — Reference Data Seed — Provincial PHN Formats
**File:** `apps/api/src/domains/reference/seeds/provincial-phn-formats.seed.ts` (NEW)
**Action:** Create seed script for all 11 province/territory PHN format definitions per MVPADD-001 §3.2.1.
**FRD ref:** MVPADD-001 §3.2.1

### Task 2.14 — Reference Unit Tests
**File:** `apps/api/src/domains/reference/reference.test.ts` (MODIFY)
**Action:** Add unit tests for all new service functions. Cover: crosswalk lookup + empty results, provider search + fuzzy matching, guidance filtering, bundling pair normalisation, anesthesia rule lookup, province detection, reciprocal rules.
**Verify:** `pnpm --filter api vitest run src/domains/reference/reference.test.ts`

### Task 2.15 — Reference Integration Tests
**File:** `apps/api/test/integration/reference/reference-extensions.test.ts` (NEW)
**Action:** Add integration tests for all new reference endpoints. Cover: crosswalk API, provider search API, guidance API, provincial formats API, bundling API, anesthesia rules API, justification templates API.
**Verify:** `pnpm --filter api vitest run test/integration/reference/`

---

## Phase 3: Patient Registry Extensions (Domain 6)

### Task 3.01 — Eligibility Cache Repository
**File:** `apps/api/src/domains/patient/patient.repository.ts` (MODIFY)
**Action:** Add functions: `getCachedEligibility(providerIdphnHash, dateOfService)`, `setCachedEligibility(entry)`, `purgeExpiredEligibilityCache()`. All scoped to `provider_id`.
**FRD ref:** MVPADD-001 §3.1.3

### Task 3.02 — Eligibility Service
**File:** `apps/api/src/domains/patient/patient.service.ts` (MODIFY)
**Action:** Add functions: `checkEligibility(ctx, phn, dateOfService)` (format validation → cache check → H-Link inquiry → cache result), `overrideEligibility(ctx, claimId, reason)`, `bulkCheckEligibility(ctx, entries[])`. Include fallback mode when H-Link unavailable.
**FRD ref:** MVPADD-001 §3.1.2, §3.1.4

### Task 3.03 — Province Detection Service Integration
**File:** `apps/api/src/domains/patient/patient.service.ts` (MODIFY)
**Action:** Add function: `detectPatientProvince(ctx, healthNumber)` — wraps the shared `detectProvince()` utility, enriches with reciprocal billing rules lookup, returns province + confidence + billing mode.
**FRD ref:** MVPADD-001 §3.2.3

### Task 3.04 — Patient Handlers — Eligibility & Province Detection
**File:** `apps/api/src/domains/patient/patient.handlers.ts` (MODIFY)
**Action:** Add handlers: `checkEligibility`, `getCachedEligibility`, `overrideEligibility`, `bulkCheckEligibility`, `detectProvince`.
**FRD ref:** MVPADD-001 §3.1.5, §3.2.5

### Task 3.05 — Patient Routes — New Endpoints
**File:** `apps/api/src/domains/patient/patient.routes.ts` (MODIFY)
**Action:** Register:
- `POST /api/v1/patients/eligibility/check`
- `GET /api/v1/patients/eligibility/cache/{phnHash}`
- `POST /api/v1/patients/eligibility/override`
- `POST /api/v1/patients/eligibility/bulk`
- `POST /api/v1/patients/detect-province`

### Task 3.06 — Patient Unit Tests — Eligibility & Reciprocal
**File:** `apps/api/src/domains/patient/patient.test.ts` (MODIFY)
**Action:** Add unit tests: Alberta PHN format pass, invalid Luhn fail, cache hit returns cached, cache miss triggers inquiry, override records audit, bulk check processes list, province detection (AB, BC, QC, ambiguous), Quebec triggers private billing.
**Verify:** `pnpm --filter api vitest run src/domains/patient/patient.test.ts`

### Task 3.07 — Patient Integration Tests — Eligibility & Reciprocal
**File:** `apps/api/test/integration/patient/eligibility.test.ts` (NEW)
**Action:** Add integration tests: eligibility check endpoint, cache behaviour, override flow, bulk check, province detection endpoint, reciprocal billing mode.
**Verify:** `pnpm --filter api vitest run test/integration/patient/`

---

## Phase 4: Provider Management Extensions (Domain 5)

### Task 4.01 — BA Subtype & Connect Care Repository
**File:** `apps/api/src/domains/provider/provider.repository.ts` (MODIFY)
**Action:** Add functions: `updateBaSubtype(ctx, baId, subtype)`, `setConnectCareUser(ctx, isConnectCare)`, `getConnectCareStatus(ctx)`. Extend existing BA queries to include `ba_subtype`.
**FRD ref:** MVPADD-001 §6.1.1; MOB-002 §6.1

### Task 4.02 — Facility & Schedule Mapping Repository
**File:** `apps/api/src/domains/provider/provider.repository.ts` (MODIFY)
**Action:** Add functions: `getFacilityMappings(ctx)`, `upsertFacilityMappings(ctx, mappings[])`, `getScheduleMappings(ctx)`, `upsertScheduleMappings(ctx, mappings[])`. All scoped to `ctx.providerId`.
**FRD ref:** MVPADD-001 §6.2.1, §6.2.2

### Task 4.03 — Smart Routing Service
**File:** `apps/api/src/domains/provider/provider.service.ts` (MODIFY)
**Action:** Add function: `resolveRoutingBa(ctx, serviceCode, facilityCode?, dateOfService)` — implements the 4-level priority chain: S-code → facility mapping → schedule mapping → primary BA fallback. Add `detectRoutingConflict(ctx, selectedBaId, resolvedBaId)`.
**FRD ref:** MVPADD-001 §6.2.3, §6.2.4

### Task 4.04 — Provider Handlers — Routing & Connect Care
**File:** `apps/api/src/domains/provider/provider.handlers.ts` (MODIFY)
**Action:** Add handlers: `getRoutingConfig`, `updateFacilityMappings`, `updateScheduleMappings`, `resolveRouting`, `setConnectCareStatus`.

### Task 4.05 — Provider Routes — New Endpoints
**File:** `apps/api/src/domains/provider/provider.routes.ts` (MODIFY)
**Action:** Register:
- `GET /api/v1/providers/me/routing-config`
- `PUT /api/v1/providers/me/routing-config/facilities`
- `PUT /api/v1/providers/me/routing-config/schedule`
- `POST /api/v1/claims/routing/resolve`

### Task 4.06 — Provider Unit Tests — Routing & ARP
**File:** `apps/api/src/domains/provider/provider.test.ts` (MODIFY)
**Action:** Add unit tests: ARP S-code forces ARP BA, facility match selects correct BA, schedule match selects correct BA, no match uses primary BA, conflict detected on manual override, routing priority chain order.
**Verify:** `pnpm --filter api vitest run src/domains/provider/`

### Task 4.07 — Provider Integration Tests — Routing
**File:** `apps/api/test/integration/provider/routing.test.ts` (NEW)
**Action:** Add integration tests: routing config CRUD, routing resolution with facility mapping, routing with schedule mapping, conflict warning response.
**Verify:** `pnpm --filter api vitest run test/integration/provider/`

---

## Phase 5: Claim Lifecycle Extensions (Domain 4.0)

### Task 5.01 — Recent Referrers Repository
**File:** `apps/api/src/domains/claim/claim.repository.ts` (MODIFY)
**Action:** Add functions: `getRecentReferrers(ctx, limit=20)`, `upsertRecentReferrer(ctx, registryId)`, `evictOldestReferrer(ctx)`. Enforce max 20 per provider.
**FRD ref:** MVPADD-001 §2.1.2

### Task 5.02 — Claim Templates Repository
**File:** `apps/api/src/domains/claim/claim.repository.ts` (MODIFY)
**Action:** Add functions: `listTemplates(ctx)`, `createTemplate(ctx, data)`, `updateTemplate(ctx, id, data)`, `deleteTemplate(ctx, id)`, `incrementTemplateUsage(ctx, id)`, `reorderTemplates(ctx, templateIds[])`.
**FRD ref:** MVPADD-001 §4.1

### Task 5.03 — Claim Justifications Repository
**File:** `apps/api/src/domains/claim/claim.repository.ts` (MODIFY)
**Action:** Add functions: `createJustification(ctx, data)`, `getJustificationForClaim(ctx, claimId)`, `updateJustification(ctx, id, data)`, `searchJustificationHistory(ctx, filters, pagination)`, `saveAsPersonalTemplate(ctx, id)`.
**FRD ref:** MVPADD-001 §4.4

### Task 5.04 — Import Batches Repository
**File:** `apps/api/src/domains/claim/claim.repository.ts` (MODIFY)
**Action:** Add functions: `createImportBatch(ctx, data)`, `getImportBatch(ctx, batchId)`, `updateImportBatchStatus(ctx, batchId, status)`, `listImportHistory(ctx, pagination)`, `checkDuplicateFile(ctx, fileHash)`.
**FRD ref:** CC-001 §10.1

### Task 5.05 — Bundling Check Service
**File:** `apps/api/src/domains/claim/claim.service.ts` (MODIFY)
**Action:** Add function: `checkBundlingConflicts(ctx, codes[], claimType, patientId?, dateOfService?)` — queries bundling rules matrix, identifies bundled pairs, recommends higher-value code, checks inclusive care periods against patient's surgical history.
**FRD ref:** MVPADD-001 §4.3.2

### Task 5.06 — Anesthesia Calculator Service
**File:** `apps/api/src/domains/claim/claim.service.ts` (MODIFY)
**Action:** Add function: `calculateAnesthesiaBenefit(ctx, procedureCodes[], startTime?, endTime?, duration?, conditionalResponses?)` — implements GR 12 rules: major procedure identification, multiple procedure reduction, compound fracture uplift, redo cardiac multipliers, time-based fallback, skin lesion cap.
**FRD ref:** MVPADD-001 §4.2.2, §4.2.3

### Task 5.07 — Text Justification Service
**File:** `apps/api/src/domains/claim/claim.service.ts` (MODIFY)
**Action:** Add functions: `generateJustificationText(templateId, fieldValues)` — merges field values into output format template, `autoDetectJustificationRequired(claimContext)` — checks for unlisted codes and inclusive care period conflicts, `autoPopulateLinkedClaimFields(claimId, linkedClaimId)`.
**FRD ref:** MVPADD-001 §4.4.4

### Task 5.08 — Template Application Service
**File:** `apps/api/src/domains/claim/claim.service.ts` (MODIFY)
**Action:** Add function: `applyTemplate(ctx, templateId, patientId, dateOfService, autoSubmit?)` — creates claim(s) from template, populates all stored fields, looks up current SOMB fees, optionally auto-submits.
**FRD ref:** MVPADD-001 §4.1.3

### Task 5.09 — Claim Handlers — Templates, Justifications, Referrers, Bundling, Anesthesia
**File:** `apps/api/src/domains/claim/claim.handlers.ts` (MODIFY)
**Action:** Add handlers for all new claim endpoints: template CRUD + apply + reorder, justification CRUD + history + save-personal, recent referrers list + record, bundling check, anesthesia calculate.

### Task 5.10 — Claim Routes — New Endpoints
**File:** `apps/api/src/domains/claim/claim.routes.ts` (MODIFY)
**Action:** Register:
- `GET/POST /api/v1/claims/templates`, `PUT/DELETE /api/v1/claims/templates/{id}`
- `POST /api/v1/claims/templates/{id}/apply`
- `PUT /api/v1/claims/templates/reorder`
- `POST /api/v1/claims/{claimId}/justification`, `GET /api/v1/claims/{claimId}/justification`
- `GET /api/v1/claims/justifications/history`
- `POST /api/v1/claims/justifications/{id}/save-personal`
- `GET/POST /api/v1/claims/referrers/recent`
- `POST /api/v1/claims/bundling/check`
- `POST /api/v1/claims/anesthesia/calculate`

### Task 5.11 — Claim Unit Tests — Extensions
**File:** `apps/api/src/domains/claim/claim.test.ts` (MODIFY)
**Action:** Add unit tests for: template CRUD + apply + quick bill, bundling check (bundled pair AHCIP, independent WCB, inclusive care), anesthesia calc (single, multiple, compound fracture, skin lesion cap, redo), justification (auto-detect, auto-populate, format generation), recent referrers (max 20 eviction).
**Verify:** `pnpm --filter api vitest run src/domains/claim/claim.test.ts`

### Task 5.12 — Claim Integration Tests — Extensions
**File:** `apps/api/test/integration/claim/claim-extensions.test.ts` (NEW)
**Action:** Integration tests for all new claim endpoints.
**Verify:** `pnpm --filter api vitest run test/integration/claim/`

---

## Phase 6: Connect Care SCC Parser (FRD 1)

### Task 6.01 — SCC Parser Service
**File:** `apps/api/src/domains/claim/scc-parser.service.ts` (NEW)
**Action:** Create the stateless SCC parser. Implement:
- Delimiter detection (comma, tab, pipe)
- Header row detection and extract type classification (AHCIP vs WCB)
- Provider identity validation (billing provider ID + BA number match)
- Row-by-row parsing against Zod schemas
- Validation rule application (blocking/warning/informational)
- `ParseResult` assembly with summary statistics
**FRD ref:** CC-001 §3

### Task 6.02 — SCC Parser — Modifier String Parsing
**File:** `apps/api/src/domains/claim/scc-parser.service.ts` (continuation)
**Action:** Implement modifier string parsing: split comma-delimited (`"CALL,COMP"`) and pipe-delimited (`"CALL|COMP|AGE"`) modifier strings into individual modifier arrays.
**FRD ref:** CC-001 §3.5

### Task 6.03 — Duplicate Detection Service
**File:** `apps/api/src/domains/claim/scc-parser.service.ts` (continuation)
**Action:** Implement `detectRowDuplicates(ctx, parsedRows[])` — for each row, query claims table on composite key (Patient ULI + Encounter Date + Service Code + Billing Provider ID) scoped to provider. Flag matches as DUPLICATE.
**FRD ref:** CC-001 §6

### Task 6.04 — Correction & Deletion Handler
**File:** `apps/api/src/domains/claim/scc-parser.service.ts` (continuation)
**Action:** Implement `handleCorrections(ctx, parsedRows[])` — for DELETED rows: find matching draft → remove or alert. For MODIFIED rows: find matching draft → replace or create new.
**FRD ref:** CC-001 §7

### Task 6.05 — SCC Parser Unit Tests
**File:** `apps/api/src/domains/claim/scc-parser.test.ts` (NEW)
**Action:** Comprehensive unit tests (all 20 cases from CC-001 §13.1): valid AHCIP, valid WCB, auto-detect extract type, provider mismatch rejection, BA mismatch rejection, missing ULI/code/future date (blocking), unrecognised code/ICD flag/stale date (warning), DELETED classification, delimiter variants, empty file, >10K rows, modifier parsing.
**Verify:** `pnpm --filter api vitest run src/domains/claim/scc-parser.test.ts`

---

## Phase 7: Connect Care Import Workflow (FRD 1)

### Task 7.01 — File Upload & Storage Service
**File:** `apps/api/src/domains/claim/connect-care-import.service.ts` (NEW)
**Action:** Implement `uploadAndParse(ctx, file)`:
- Validate file extension (.csv, .CSV, .xlsx, .xls) and size (≤10 MB)
- Store raw file in DO Spaces at `imports/{provider_id}/{yyyy-mm}/{uuid}.{ext}`
- If .xlsx/.xls: convert to CSV
- Pass CSV to SCC parser
- Run duplicate detection
- Run correction/deletion handling
- Create import_batch record (status=PENDING)
- Return ParseResult + importBatchId
- Audit log: CONNECT_CARE_IMPORT_UPLOADED
**FRD ref:** CC-001 §4.2

### Task 7.02 — Import Confirmation Service
**File:** `apps/api/src/domains/claim/connect-care-import.service.ts` (continuation)
**Action:** Implement `confirmImport(ctx, batchId)`:
- For each VALID/WARNING row: create claim in DRAFT state via claim creation service
- Tag claims with import_source, import_batch_id, raw_file_reference, scc_charge_status
- Handle ICD conversion flags (blank ICD-9, preserve icd10_source_code)
- Route WCB rows to WCB pipeline
- Skip DUPLICATE rows (unless physician chose create)
- Process DELETED rows per correction handler
- Update import batch: status=CONFIRMED, claims_created count
- Audit log: CONNECT_CARE_IMPORT_CONFIRMED
**FRD ref:** CC-001 §4.4

### Task 7.03 — Import Cancel & History Service
**File:** `apps/api/src/domains/claim/connect-care-import.service.ts` (continuation)
**Action:** Implement `cancelImport(ctx, batchId)`, `getImportHistory(ctx, pagination)`, `getImportBatchDetail(ctx, batchId)`.
**FRD ref:** CC-001 §11.1

### Task 7.04 — Connect Care Import Handlers
**File:** `apps/api/src/domains/claim/claim.handlers.ts` (MODIFY)
**Action:** Add handlers: `uploadConnectCareImport`, `getImportBatch`, `confirmImport`, `cancelImport`, `getImportHistory`.

### Task 7.05 — Connect Care Import Routes
**File:** `apps/api/src/domains/claim/claim.routes.ts` (MODIFY)
**Action:** Register:
- `POST /api/v1/claims/connect-care/import` (multipart/form-data)
- `GET /api/v1/claims/connect-care/import/{batchId}`
- `POST /api/v1/claims/connect-care/import/{batchId}/confirm`
- `POST /api/v1/claims/connect-care/import/{batchId}/cancel`
- `GET /api/v1/claims/connect-care/import/history`

### Task 7.06 — Connect Care Import Integration Tests
**File:** `apps/api/test/integration/claims/connect-care-import.test.ts` (NEW)
**Action:** All 12 integration tests from CC-001 §13.2: upload→parse→confirm→claims created, cancel→no claims, warnings preserved, ICD conversion flags, DELETED/MODIFIED handling, duplicates skip/create, WCB routing, history scoping, crosswalk lookup.
**Verify:** `pnpm --filter api vitest run test/integration/claims/`

---

## Phase 8: Intelligence Engine Extensions (Domain 7)

### Task 8.01 — Bedside-Contingent Rule Evaluation
**File:** `apps/api/src/domains/intel/intel.service.ts` (MODIFY)
**Action:** Modify the rule evaluation flow to implement the three-tier confidence model for bedside-contingent rules:
- Check Tier A signals (import source, shift data, weekend/holiday, multi-row encounter)
- If no Tier A: query `ai_provider_learning` for acceptance rate
- Assign tier: A (auto-apply), B (pre-apply), C (suggestion), or SUPPRESS
- Generate suggestion with assigned tier
**FRD ref:** MVPADD-001 §5.2.2

### Task 8.02 — Learning Loop Adjustment
**File:** `apps/api/src/domains/intel/intel.service.ts` (MODIFY)
**Action:** Modify learning loop for bedside-contingent rules:
- Tier A auto-applications tracked but don't affect acceptance rate
- Tier B keeps → increment times_accepted
- Tier B removes → increment pre_applied_removed_count + times_dismissed; demote to C if removal rate >50% over last 10
**FRD ref:** MVPADD-001 §5.2.4

### Task 8.03 — Unbilled WCB Opportunity Rule
**File:** `apps/api/src/domains/intel/intel.seed.ts` (MODIFY)
**Action:** Add new Tier 1 rule definition: `UNBILLED_WCB_OPPORTUNITY`. Condition: patient has active WCB claim AND AHCIP claim being submitted. Priority: HIGH.
**FRD ref:** MVPADD-001 §5.1.1

### Task 8.04 — Periodic Summary Digest Service
**File:** `apps/api/src/domains/intel/intel.digest.service.ts` (NEW)
**Action:** Create scheduled job: aggregate suggestions per provider for billing period. Produce digest: total generated, accepted, revenue impact, top categories. Emit `INTEL_WEEKLY_DIGEST` notification event.
**FRD ref:** MVPADD-001 §5.1.2

### Task 8.05 — Intelligence Unit Tests — Confidence Tiers
**File:** `apps/api/src/domains/intel/intel.test.ts` (MODIFY)
**Action:** Add unit tests: shift encounter → Tier A auto-apply, weekend → Tier A, acceptance >70% w/ 5+ showings → Tier B, 30-70% → Tier C, <30% w/ 10+ → suppress, Tier B removal → updates counts, WCB opportunity rule fires correctly.
**Verify:** `pnpm --filter api vitest run src/domains/intel/`

### Task 8.06 — Intelligence Integration Tests
**File:** `apps/api/test/integration/intel/confidence-tiers.test.ts` (NEW)
**Action:** Integration tests: rule evaluation with Connect Care import source, pre-apply + opt-out flow, digest generation.
**Verify:** `pnpm --filter api vitest run test/integration/intel/`

---

## Phase 9: Mobile Companion v2 (Domain 10)

### Task 9.01 — Shift Schedules Repository
**File:** Locate existing mobile repository file (MODIFY)
**Action:** Add functions: `createShiftSchedule(ctx, data)`, `updateShiftSchedule(ctx, id, data)`, `deleteShiftSchedule(ctx, id)`, `listShiftSchedules(ctx, dateRange)`, `getShiftSchedule(ctx, id)`. All scoped to `ctx.providerId`.
**FRD ref:** MOB-002 §3.1

### Task 9.02 — RRULE Expansion Service
**File:** `apps/api/src/domains/mobile/services/rrule.service.ts` (NEW)
**Action:** Implement `expandRrule(rrule, effectiveFrom, effectiveUntil, windowDays=90)` — expands iCal RRULE strings into concrete date instances. Support FREQ=WEEKLY, FREQ=MONTHLY, BYDAY, INTERVAL. Handle overnight shifts (end < start = next day).
**FRD ref:** MOB-002 §3.1.2

### Task 9.03 — Shift Schedule Service
**File:** Locate existing mobile service (MODIFY)
**Action:** Add functions: `createSchedule(ctx, data)`, `updateSchedule(ctx, id, data)`, `deleteSchedule(ctx, id)`, `getCalendarInstances(ctx, from, to)` — materialises shift instances from RRULE for date range, `createInferredShift(ctx, scheduleId)` — creates implicit shift record when scheduled shift not manually started.
**FRD ref:** MOB-002 §3.1, §3.3

### Task 9.04 — Shift Reminder Service
**File:** Locate existing mobile service (MODIFY)
**Action:** Add function: `processShiftReminders()` — scheduled job that checks upcoming shifts within reminder window, emits `SHIFT_REMINDER` events. Add `processFollowupReminders()` — checks shifts 15min past start with no manual start, emits `SHIFT_FOLLOWUP_REMINDER`.
**FRD ref:** MOB-002 §3.2

### Task 9.05 — Encounter Logging Repository
**File:** Locate existing mobile repository (MODIFY)
**Action:** Add/extend functions: `logEncounter(ctx, shiftId, data)` — stores PHN (full or partial), capture method, timestamp, free-text tag. `listEncounters(ctx, shiftId)`, `deleteEncounter(ctx, shiftId, encounterId)`. Enforce active shift requirement.
**FRD ref:** MOB-002 §4

### Task 9.06 — Encounter Logging Service
**File:** Locate existing mobile service (MODIFY)
**Action:** Add functions: `logEncounter(ctx, shiftId, phn, captureMethod, isPartial, freeTextTag?)` — validates PHN format (or accepts last-4), records with timestamp, audit logs. `deleteEncounter(ctx, shiftId, encounterId)`.
**FRD ref:** MOB-002 §4.2

### Task 9.07 — Shift & Schedule Handlers
**File:** Locate existing mobile handlers/routes (MODIFY)
**Action:** Add handlers for: schedule CRUD, calendar instances, shift start/end/active/list/detail, confirm-inferred, encounter log/list/delete.

### Task 9.08 — Mobile Routes — New Endpoints
**File:** Locate existing mobile routes (MODIFY)
**Action:** Register all endpoints from MOB-002 §8.1–8.3:
- Schedule: `GET/POST /api/v1/mobile/schedules`, `PUT/DELETE /api/v1/mobile/schedules/{id}`, `GET /api/v1/mobile/schedules/calendar`
- Shifts: `POST /api/v1/mobile/shifts/start`, `POST /api/v1/mobile/shifts/{id}/end`, `GET /api/v1/mobile/shifts/active`, `GET /api/v1/mobile/shifts`, `GET /api/v1/mobile/shifts/{id}`, `POST /api/v1/mobile/shifts/{id}/confirm-inferred`
- Encounters: `POST /api/v1/mobile/shifts/{shiftId}/encounters`, `GET /api/v1/mobile/shifts/{shiftId}/encounters`, `DELETE /api/v1/mobile/shifts/{shiftId}/encounters/{id}`

### Task 9.09 — Mobile Unit Tests — Schedules, Encounters, Reminders
**File:** Add to existing mobile test files (MODIFY)
**Action:** Add unit tests from MOB-002 §10.1: one-off shift, RRULE expansion, overnight interpretation, reminder generation, follow-up reminder, forgotten shift inference, all 4 encounter capture methods, invalid Luhn rejection, active shift requirement.
**Verify:** `pnpm --filter api vitest run src/domains/mobile/`

### Task 9.10 — Mobile Integration Tests — Schedules & Encounters
**File:** `apps/api/test/integration/mobile/schedules-encounters.test.ts` (NEW)
**Action:** Integration tests from MOB-002 §10.2: create schedule → start shift → log encounters → end shift → verify. RRULE calendar endpoint. Start from reminder. Inferred shift flow.
**Verify:** `pnpm --filter api vitest run test/integration/mobile/`

---

## Phase 10: Reconciliation (FRD 3 C4)

Depends on: Phase 7 (CC import), Phase 9 (encounter logging), Phase 8 (intelligence engine Tier A signals).

### Task 10.01 — Reconciliation Matching Service
**File:** `apps/api/src/domains/claim/reconciliation.service.ts` (NEW)
**Action:** Implement `reconcileImportWithShift(ctx, importBatchId)`:
- Find matching shift (date + facility)
- For each SCC row: match on PHN + date + facility against encounter log
- Classify into 4 categories: full match, unmatched SCC, unmatched encounter, shift-only
- For full matches: assign `inferred_service_time` from encounter `logged_at`
- For partial PHN: resolve last-4 against SCC ULIs
- Calculate modifier eligibility (AFHR, NGHT) based on timestamps
- Produce reconciliation summary
**FRD ref:** MOB-002 §5.1–5.7

### Task 10.02 — Reconciliation Confirmation Service
**File:** `apps/api/src/domains/claim/reconciliation.service.ts` (continuation)
**Action:** Implement `confirmReconciliation(ctx, batchId)`:
- Apply inferred_service_time to matched claims
- Apply modifiers (Tier A deterministic per B4a)
- Link encounters to claims (matched_claim_id)
- Generate missed billing notifications for unmatched encounters
- Audit log: RECONCILIATION_CONFIRMED
**FRD ref:** MOB-002 §5.4

### Task 10.03 — Reconciliation Resolution Services
**File:** `apps/api/src/domains/claim/reconciliation.service.ts` (continuation)
**Action:** Implement:
- `resolveUnmatchedTime(ctx, batchId, claimId, inferredServiceTime)` — physician provides time for unmatched SCC row
- `resolvePartialPhn(ctx, batchId, encounterId, selectedPatientUli)` — physician disambiguates partial PHN match
**FRD ref:** MOB-002 §5.5, §5.9

### Task 10.04 — Reconciliation Handlers
**File:** `apps/api/src/domains/claim/claim.handlers.ts` (MODIFY)
**Action:** Add handlers: `triggerReconciliation`, `getReconciliationResult`, `confirmReconciliation`, `resolveTime`, `resolvePartialPhn`.

### Task 10.05 — Reconciliation Routes
**File:** `apps/api/src/domains/claim/claim.routes.ts` (MODIFY)
**Action:** Register:
- `POST /api/v1/claims/connect-care/reconcile`
- `GET /api/v1/claims/connect-care/reconcile/{batchId}`
- `POST /api/v1/claims/connect-care/reconcile/{batchId}/confirm`
- `POST /api/v1/claims/connect-care/reconcile/{batchId}/resolve-time`
- `POST /api/v1/claims/connect-care/reconcile/{batchId}/resolve-partial`

### Task 10.06 — Reconciliation Unit Tests
**File:** `apps/api/src/domains/claim/reconciliation.test.ts` (NEW)
**Action:** All unit tests from MOB-002 §10.1 (Reconciliation section): full match, unmatched SCC shift-only modifier, unmatched SCC boundary crossing, unmatched encounter missed billing, shift-only fallback, multi-row same timestamp, partial PHN 1-match/0-match/multi-match, AFHR/NGHT rules.
**Verify:** `pnpm --filter api vitest run src/domains/claim/reconciliation.test.ts`

### Task 10.07 — Reconciliation Integration Tests
**File:** `apps/api/test/integration/claims/reconciliation.test.ts` (NEW)
**Action:** Integration tests from MOB-002 §10.2: upload CSV → reconcile → matches → modifiers → claims updated. No shift → no reconciliation. Inferred shift reconciliation. Missed billing notification.
**Verify:** `pnpm --filter api vitest run test/integration/claims/`

---

## Phase 11: Security Tests

All 6 mandatory security test categories for every new/modified endpoint group. These run AFTER functional code is complete.

### Task 11.01 — Connect Care Import — authn.security.ts
**File:** `apps/api/test/security/claims/connect-care.authn.security.ts` (NEW)
**Action:** 401 test for every CC import + crosswalk endpoint (5 import + 2 crosswalk = 7 tests).
**FRD ref:** CC-001 §13.3

### Task 11.02 — Connect Care Import — authz.security.ts
**File:** `apps/api/test/security/claims/connect-care.authz.security.ts` (NEW)
**Action:** Delegate permission tests: without CLAIM_CREATE → 403 on upload/confirm; with CLAIM_CREATE → 200.
**FRD ref:** CC-001 §13.3

### Task 11.03 — Connect Care Import — scoping.security.ts
**File:** `apps/api/test/security/claims/connect-care.scoping.security.ts` (NEW)
**Action:** Physician 1 import not accessible by Physician 2 (404), SCC file with wrong provider ID rejected, history scoped.
**FRD ref:** CC-001 §13.3

### Task 11.04 — Connect Care Import — input.security.ts
**File:** `apps/api/test/security/claims/connect-care.input.security.ts` (NEW)
**Action:** SQL injection in CSV fields, XSS in patient name, file >10MB, non-CSV file, malformed CSV.
**FRD ref:** CC-001 §13.3

### Task 11.05 — Connect Care Import — leakage.security.ts
**File:** `apps/api/test/security/claims/connect-care.leakage.security.ts` (NEW)
**Action:** Parse errors don't echo PHN, 500 errors sanitised, import history masks PHN.
**FRD ref:** CC-001 §13.3

### Task 11.06 — Connect Care Import — audit.security.ts
**File:** `apps/api/test/security/claims/connect-care.audit.security.ts` (NEW)
**Action:** Upload → UPLOADED audit, confirm → CONFIRMED, cancel → CANCELLED, correction → CORRECTION, crosswalk → RESOLVED.
**FRD ref:** CC-001 §13.3

### Task 11.07 — Reference Extensions — authn.security.ts
**File:** `apps/api/test/security/reference/reference-ext.authn.security.ts` (NEW)
**Action:** 401 test for every new reference endpoint (~15 endpoints).
**FRD ref:** MVPADD-001 §9.3

### Task 11.08 — Reference Extensions — authz.security.ts
**File:** `apps/api/test/security/reference/reference-ext.authz.security.ts` (NEW)
**Action:** Admin-only guidance CRUD → 403 for physician. Physician can read guidance/search.
**FRD ref:** MVPADD-001 §9.3

### Task 11.09 — Claim Extensions — authn.security.ts
**File:** `apps/api/test/security/claims/claim-ext.authn.security.ts` (NEW)
**Action:** 401 for every new claim endpoint (~15: templates, justifications, referrers, bundling, anesthesia, reconciliation).

### Task 11.10 — Claim Extensions — authz.security.ts
**File:** `apps/api/test/security/claims/claim-ext.authz.security.ts` (NEW)
**Action:** Delegate without CLAIM_CREATE → 403 on template apply, justification create. With CLAIM_VIEW → 200 on template list.

### Task 11.11 — Claim Extensions — scoping.security.ts
**File:** `apps/api/test/security/claims/claim-ext.scoping.security.ts` (NEW)
**Action:** Physician 1 templates/justifications/referrers/routing not visible to Physician 2. Cross-provider returns 404.

### Task 11.12 — Claim Extensions — input.security.ts
**File:** `apps/api/test/security/claims/claim-ext.input.security.ts` (NEW)
**Action:** SQL injection in search queries, XSS in template names/justification text, non-UUID params, negative anesthesia time.

### Task 11.13 — Claim Extensions — leakage.security.ts
**File:** `apps/api/test/security/claims/claim-ext.leakage.security.ts` (NEW)
**Action:** Eligibility errors don't echo PHN, justification text not in error responses, 500 sanitised.

### Task 11.14 — Claim Extensions — audit.security.ts
**File:** `apps/api/test/security/claims/claim-ext.audit.security.ts` (NEW)
**Action:** Template CRUD → audit entries, justification CRUD → audit, bundling/anesthesia/routing overrides → audit, Tier A/B auto/pre-application → audit.

### Task 11.15 — Patient Extensions — Security Tests (all 6 categories)
**File:** `apps/api/test/security/patient/patient-ext.{authn,authz,scoping,input,leakage,audit}.security.ts` (6 NEW files)
**Action:** Cover: eligibility endpoints 401, delegate permissions, cross-provider eligibility cache isolation, PHN injection attempts, eligibility errors don't leak PHN, eligibility check/override audit entries.

### Task 11.16 — Provider Extensions — Security Tests (all 6 categories)
**File:** `apps/api/test/security/provider/provider-ext.{authn,authz,scoping,input,leakage,audit}.security.ts` (6 NEW files)
**Action:** Cover: routing endpoints 401, delegate permissions for routing config, cross-provider routing config isolation, invalid facility/schedule mappings, routing errors don't leak details, routing config change audit.

### Task 11.17 — Mobile v2 — Security Tests (all 6 categories)
**File:** `apps/api/test/security/mobile/mobile-v2.{authn,authz,scoping,input,leakage,audit}.security.ts` (6 NEW files)
**Action:** Cover all per MOB-002 §10.3: every schedule/shift/encounter/reconciliation endpoint 401, SHIFT_MANAGE permission, cross-provider isolation (schedules/encounters/reconciliation), PHN injection/invalid RRULE/XSS in free_text_tag, encounter errors don't echo PHN, shift/encounter/reconciliation audit trail.

### Task 11.18 — Intelligence Extensions — Security Tests
**File:** `apps/api/test/security/intel/intel-ext.{authn,authz,scoping,input,leakage,audit}.security.ts` (6 NEW files)
**Action:** Cover: digest endpoint 401, Tier A/B auto-apply doesn't bypass auth, cross-provider learning isolation, confidence tier audit entries.

---

## Summary

| Phase | Tasks | New Files | Modified Files | Key Deliverables |
|-------|-------|-----------|----------------|------------------|
| 1. Schema Foundation | 22 | 3 | 13 | 16 new tables, 6 modified tables, all Zod schemas, migration |
| 2. Reference Data | 15 | 3 | 5 | ICD crosswalk, provider registry, billing guidance, bundling, anesthesia, justification APIs |
| 3. Patient Registry | 7 | 1 | 4 | Eligibility verification, province detection, reciprocal billing |
| 4. Provider Management | 7 | 1 | 4 | ARP BA subtypes, smart routing, Connect Care flag |
| 5. Claim Lifecycle | 12 | 1 | 5 | Templates, justifications, bundling check, anesthesia calc, recent referrers |
| 6. SCC Parser | 5 | 2 | 0 | Stateless parser, duplicate detection, correction handling |
| 7. CC Import Workflow | 6 | 2 | 2 | Upload, parse, confirm/cancel, history |
| 8. Intelligence Engine | 6 | 2 | 2 | Confidence tiers, WCB opportunity rule, weekly digest |
| 9. Mobile v2 | 10 | 2 | ~5 | Shift schedules, RRULE, encounter logging, reminders |
| 10. Reconciliation | 7 | 3 | 2 | PHN matching, modifier application, missed billing alerts |
| 11. Security Tests | 18 | ~36 | 0 | All 6 categories for every endpoint group |
| **TOTAL** | **115** | **~56** | **~42** | |

### Critical Path Dependencies

```
1 → 2 → 5 → 6 → 7 ─────────────────────┐
1 → 3 ───────────────────────────────────┤
1 → 4 ───────────────────────────────────┤
1 → 8 (after 5, 7) ─────────────────────┤
1 → 9 ───────────────────────────────────┤
                                         ├→ 10 (requires 7 + 8 + 9) → 11
```

Phases 2, 3, 4 can run in parallel after Phase 1.
Phases 5 depends on 2 (reference data).
Phase 6 depends on 5 (claim model extensions).
Phase 7 depends on 6 (SCC parser).
Phase 8 depends on 5 + 7 (claim model + import source field).
Phase 9 can run in parallel with 6/7/8 after Phase 4.
Phase 10 requires 7 + 8 + 9 (import + intelligence + encounters).
Phase 11 runs after each phase's functional code is complete (can be incremental).
