# Task FRD-14: Update Domain 13 (Support System) FRD

## Objective

Read the current Domain 13 FRD and the actual implementation, then update the FRD in-place. The implementation uses a subdirectory structure. Sync documentation with actual feature set.

## Step 1: Read Current FRD

Read the full file:
- `docs/frd/extracted/Meritum_Domain_13_Support_System.md`

## Step 2: Read Implementation

**Domain module (subdirectory structure):**

Repositories:
- `apps/api/src/domains/support/repos/help-articles.repo.ts`
- `apps/api/src/domains/support/repos/support-tickets.repo.ts`

Routes:
- `apps/api/src/domains/support/routes/help.routes.ts`
- `apps/api/src/domains/support/routes/ticket.routes.ts`

Services:
- `apps/api/src/domains/support/services/help-centre.service.ts`
- `apps/api/src/domains/support/services/support-ticket.service.ts`

**Shared constants:**
- `packages/shared/src/constants/support.constants.ts`

**Test files:**
- `apps/api/src/domains/support/repos/help-articles.repo.test.ts`
- `apps/api/src/domains/support/repos/support-tickets.repo.test.ts`
- `apps/api/src/domains/support/routes/help.routes.test.ts`
- `apps/api/src/domains/support/routes/ticket.routes.test.ts`
- `apps/api/src/domains/support/services/help-centre.service.test.ts`
- `apps/api/src/domains/support/services/support-ticket.service.test.ts`

**Help centre content:**
- Check the `help-centre/` directory at the project root for the 43 markdown articles across 6 categories

## Step 3: Read Supplementary Specs

No supplementary specs specifically target Domain 13. Compare implementation against the original FRD.

## Step 4: Key Changes to Incorporate

1. **Subdirectory architecture** — Implementation uses repos/, routes/, services/ subdirectories rather than the standard 5-file pattern. Document this.

2. **Help centre articles** — 43 articles in 6 categories:
   - getting-started/ (6 articles)
   - billing-reference/ (8 articles)
   - submitting-claims/ (9 articles)
   - after-submission/ (4 articles)
   - security-compliance/ (8 articles)
   - your-account/ (8 articles)
   Verify the FRD's category structure matches.

3. **Full-text search** — Verify the FRD documents the full-text search implementation for help articles (pg_trgm or tsvector).

4. **Support tickets** — Check the ticket model:
   - Ticket status workflow (OPEN → IN_PROGRESS → WAITING → RESOLVED → CLOSED or similar)
   - Priority levels and SLA targets (URGENT <2h, HIGH <4h, MEDIUM <1 business day)
   - Auto-captured context (page URL, claim ID, error codes)

5. **Context-aware help** — Verify the FRD documents how help articles are surfaced contextually (e.g., viewing a claim page shows billing-related articles).

6. **Satisfaction ratings** — Check if the implementation includes a feedback/satisfaction mechanism for help articles and support tickets.

7. **Article validation** — The project includes `scripts/validate-article.js` and `scripts/validate-all-articles.js` for content quality enforcement. Document the article format requirements if relevant.

8. **Phase 1.5 AI chat** — Check the FRD for planned AI chat features. If not yet implemented, keep the section but note it as Phase 1.5 (deferred).

## Step 5: Write Updated FRD

Write the complete updated FRD to: `docs/frd/extracted/Meritum_Domain_13_Support_System.md`

### Format Rules

- Preserve existing section structure and formal writing style
- Note the subdirectory module structure
- Update help centre categories to match the actual 43 articles
- Update ticket model, SLA targets, and status workflow to match implementation
- Update data model and API contracts
- Keep Phase 1.5 AI chat as a planned future section if not yet implemented
- Do not add TODO/TBD/placeholder content for implemented features

When complete, output on its own line: [TASK_COMPLETE]
If blocked, output: [TASK_BLOCKED] reason: <explanation>
