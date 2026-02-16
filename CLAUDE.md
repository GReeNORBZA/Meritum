# CLAUDE.md — Meritum Health Technologies

## Project Overview

Meritum is a self-serve billing platform for Alberta physicians. It handles AHCIP claim submission via H-Link and WCB Alberta claim submission via Electronic Injury Reporting. Target users: rural GPs and specialists underserved by existing billing solutions.

- **Product:** meritum.ca
- **Company:** Meritum Health Technologies Inc. (separate from SigOct)
- **Pricing:** $279/month, $2,790/year, $199/month early bird (first 12 months, first 100 physicians)
- **Infrastructure:** DigitalOcean Toronto (Canadian data residency required by HIA)
- **Regulatory:** Health Information Act (Alberta), FOIP, PIPEDA

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | TypeScript (strict mode, all packages) |
| Backend API | Fastify 5.x |
| Frontend | Next.js 15.x (App Router) |
| Database | PostgreSQL 16 (DigitalOcean Managed, Toronto) |
| ORM | Drizzle ORM |
| Auth | Lucia (session management) + custom IAM |
| Monorepo | Turborepo + pnpm workspaces |
| Testing | Vitest + Supertest (API) + Playwright (E2E) |
| Real-time | @fastify/websocket |
| Email | Postmark (transactional only) |
| File Storage | DigitalOcean Spaces (Toronto, S3-compatible) |
| Deployment | DigitalOcean App Platform |
| Validation | Zod (shared between API and frontend) |
| UI Components | shadcn/ui + Tailwind CSS |
| Charts | Recharts |

## Project Structure

```
meritum/
├── CLAUDE.md                    # This file
├── turbo.json
├── pnpm-workspace.yaml
├── apps/
│   ├── api/                     # Fastify backend
│   │   ├── src/
│   │   │   ├── domains/         # Domain modules (1 folder per domain)
│   │   │   │   ├── iam/         # Domain 1: Identity & Access
│   │   │   │   ├── reference/   # Domain 2: Reference Data
│   │   │   │   ├── notify/      # Domain 3/9: Notification Service
│   │   │   │   ├── claims/      # Domain 4.0: Claim Lifecycle Core
│   │   │   │   ├── ahcip/       # Domain 4.1: AHCIP Pathway
│   │   │   │   ├── wcb/         # Domain 4.2: WCB Pathway
│   │   │   │   ├── providers/   # Domain 5: Provider Management
│   │   │   │   ├── patients/    # Domain 6: Patient Registry
│   │   │   │   ├── intel/       # Domain 7: Intelligence Engine
│   │   │   │   ├── analytics/   # Domain 8: Analytics & Reporting
│   │   │   │   ├── platform/    # Domain 12: Platform Operations
│   │   │   │   └── support/     # Domain 13: Support System
│   │   │   ├── plugins/         # Fastify plugins (auth, cors, rate-limit)
│   │   │   ├── middleware/      # Request hooks (physician scoping, audit)
│   │   │   ├── lib/             # Shared utilities (errors, pagination, logging)
│   │   │   └── server.ts        # Fastify server bootstrap
│   │   ├── test/
│   │   │   ├── fixtures/        # Test fixtures (createTestPhysician, etc.)
│   │   │   ├── integration/     # API integration tests (per domain)
│   │   │   └── unit/            # Unit tests (per domain)
│   │   └── drizzle/             # Migration files
│   │       └── migrations/
│   └── web/                     # Next.js frontend
│       ├── src/
│       │   ├── app/             # App Router pages
│       │   ├── components/      # UI components
│       │   │   ├── ui/          # shadcn/ui primitives
│       │   │   └── domain/      # Domain-specific components
│       │   ├── hooks/           # React hooks
│       │   ├── lib/             # Frontend utilities
│       │   └── styles/          # Tailwind config, globals
│       └── test/
│           └── e2e/             # Playwright E2E tests
├── packages/
│   └── shared/                  # Shared between API and frontend
│       ├── src/
│       │   ├── schemas/         # Zod validation schemas (per domain)
│       │   ├── types/           # TypeScript types derived from Zod
│       │   ├── constants/       # Enums, status codes, permission keys
│       │   └── utils/           # Pure functions (PHN validation, fee calc)
│       └── package.json
└── docs/
    └── frd/                     # Functional Requirements Documents
```

## Domain Module Structure

Every domain module in `apps/api/src/domains/` follows the same structure:

```
domains/{name}/
├── {name}.routes.ts      # Fastify route definitions (URL, method, schema, handler ref)
├── {name}.handlers.ts    # Request handlers (thin: validate, call service, respond)
├── {name}.service.ts     # Business logic (all domain rules live here)
├── {name}.repository.ts  # Database queries (Drizzle). Only file that touches DB.
├── {name}.schema.ts      # Re-exports from @meritum/shared for this domain's Zod schemas
└── {name}.test.ts        # Unit tests for service layer
```

**Rules:**
- Handlers never call repositories directly. Always go through the service.
- Repositories never contain business logic. Only data access.
- Services receive dependencies via function parameters, not global imports (testable).
- Routes define Fastify schemas using Zod (via fastify-type-provider-zod) for automatic request/response validation.

## Database Conventions

### Naming
- Tables: `snake_case`, plural (`providers`, `claims`, `business_arrangements`)
- Columns: `snake_case` (`date_of_service`, `health_service_code`)
- Primary keys: `{singular}_id` as UUID (`provider_id`, `claim_id`)
- Foreign keys: match the referenced column name (`provider_id UUID REFERENCES providers(provider_id)`)
- Timestamps: `created_at`, `updated_at` on every table. Type: `TIMESTAMPTZ`. Default: `now()`.
- Boolean columns: `is_` prefix (`is_active`, `is_suppressed`)

### Schema Definition
- Define all tables in `packages/shared/src/schemas/db/` using Drizzle's schema syntax
- One file per domain: `iam.schema.ts`, `claims.schema.ts`, `providers.schema.ts`, etc.
- Export from `packages/shared/src/schemas/db/index.ts`
- All indexes defined in schema file, not in separate migrations

### Migrations
- Generated from Drizzle schema via `drizzle-kit generate`
- Stored in `apps/api/drizzle/migrations/`
- Never edit generated migration files manually
- Run via `drizzle-kit migrate`

### Physician Scoping (CRITICAL)
Every query that touches PHI must include `WHERE provider_id = :authenticatedProviderId`. This is enforced at the repository layer. Never rely on the handler to pass the correct provider_id — extract it from the authenticated session context inside the repository function.

```typescript
// CORRECT — repository extracts provider_id from context
async function getPatients(ctx: AuthContext, filters: PatientFilters) {
  return db.select().from(patients)
    .where(eq(patients.providerId, ctx.providerId))  // Always scoped
    .where(/* ...additional filters... */);
}

// WRONG — handler passes provider_id as a parameter
async function getPatients(providerId: string, filters: PatientFilters) { ... }
```

### Soft Deletes
Use `is_active BOOLEAN DEFAULT true` for soft deletes on: patients, providers, business_arrangements, delegate_relationships. Add `.where(eq(table.isActive, true))` to all default queries. Hard deletes only for: analytics cache, digest queue, expired sessions.

## API Conventions

### URL Pattern
```
/api/v1/{domain}/{resource}
/api/v1/{domain}/{resource}/{id}
/api/v1/{domain}/{resource}/{id}/{sub-resource}
/api/v1/internal/{domain}/{resource}   # Internal-only endpoints (no external access)
```

### Request/Response Format
- All request bodies: JSON
- All responses: `{ data: T }` for success, `{ error: { code: string, message: string, details?: any } }` for errors
- Pagination: `{ data: T[], pagination: { total: number, page: number, pageSize: number, hasMore: boolean } }`
- Dates: ISO 8601 strings in responses (`2026-02-13T14:30:00.000Z`)
- Money: `string` type with 2 decimal places (`"279.00"`) — never floating point
- IDs: UUID strings

### HTTP Status Codes
- 200: Success (GET, PUT, PATCH)
- 201: Created (POST that creates a resource)
- 204: No content (DELETE)
- 400: Validation error (Zod validation failure)
- 401: Not authenticated
- 403: Forbidden (authenticated but insufficient permissions)
- 404: Resource not found (or not accessible to this physician — don't leak existence)
- 409: Conflict (duplicate, state machine violation)
- 422: Business rule violation (valid request but violates domain rules)
- 500: Internal server error

### Rate Limiting
- Default: 100 requests/minute per authenticated user
- Auth endpoints (login, MFA): 10 requests/minute per IP
- File uploads: 5 requests/minute per user
- Internal endpoints: no rate limiting (service-to-service)

## Validation Schemas (Zod)

All Zod schemas live in `packages/shared/src/schemas/` so they're shared between API and frontend.

```typescript
// packages/shared/src/schemas/claims.schema.ts
import { z } from 'zod';

export const createAhcipClaimSchema = z.object({
  patientId: z.string().uuid(),
  healthServiceCode: z.string().min(1).max(10),
  dateOfService: z.string().date(),
  diagnosticCode: z.string().optional(),
  modifier1: z.string().max(4).optional(),
  modifier2: z.string().max(4).optional(),
  modifier3: z.string().max(4).optional(),
  locationId: z.string().uuid(),
  referringProviderId: z.string().uuid().optional(),
  textAmount: z.string().regex(/^\d+\.\d{2}$/).optional(),
  encounterType: z.enum(['OFFICE', 'HOSPITAL', 'ED', 'VIRTUAL', 'FACILITY']),
  timeSpent: z.number().int().positive().optional(),
});

export type CreateAhcipClaim = z.infer<typeof createAhcipClaimSchema>;
```

API routes reference these schemas for automatic validation:

```typescript
// apps/api/src/domains/ahcip/ahcip.routes.ts
app.post('/api/v1/ahcip/claims', {
  schema: { body: createAhcipClaimSchema },
  handler: ahcipHandlers.createClaim,
});
```

## Authentication & Authorization

### Session Model
- Lucia manages session cookies (HttpOnly, Secure, SameSite=Lax)
- Sessions stored in PostgreSQL (`user_sessions` table)
- Session duration: 24 hours, sliding window refresh
- MFA: TOTP via otplib, required for all physician accounts

### Auth Context
Every authenticated request has an `AuthContext` available:

```typescript
interface AuthContext {
  userId: string;           // User account ID
  providerId: string;       // Provider (physician) ID — null for admin users
  role: 'physician' | 'delegate' | 'admin';
  delegateContext?: {
    delegateUserId: string;
    physicianProviderId: string;
    permissions: Permission[];
  };
}
```

### Permission Checking
Use a `requirePermission` guard in routes:

```typescript
app.get('/api/v1/claims', {
  preHandler: [requireAuth, requirePermission('CLAIM_VIEW')],
  handler: claimHandlers.list,
});
```

For delegates, `requirePermission` checks the delegate's permission set for their active physician context (Domain 5 delegate_relationships table).

### Password Hashing
- Algorithm: Argon2id
- Library: `@node-rs/argon2` (native binding, fastest option)
- Parameters: memory 19456 KiB, iterations 2, parallelism 1

## Security Defaults

**Always apply these unless explicitly overridden by the FRD:**
- Encrypt all data at rest (DigitalOcean Managed DB + Spaces handle this)
- TLS everywhere (App Platform provides this)
- CORS: allow only meritum.ca origins
- Helmet headers on all responses (via @fastify/helmet)
- Request IDs on every request (correlation ID for logging)
- Audit log every state change on claims, providers, patients, delegates, subscriptions
- PHN masking in logs: first 3 digits visible, rest replaced with asterisks (`123******`)
- No PHI in email bodies — only links to authenticated pages
- No PHI in error messages or API error responses
- H-Link credentials stored in DigitalOcean environment variables, never in database
- Stripe Customer objects never receive PHI

## Error Handling

Use a centralized error class hierarchy:

```typescript
// apps/api/src/lib/errors.ts
export class AppError extends Error {
  constructor(
    public statusCode: number,
    public code: string,
    message: string,
    public details?: unknown
  ) {
    super(message);
  }
}

export class ValidationError extends AppError {
  constructor(message: string, details?: unknown) {
    super(400, 'VALIDATION_ERROR', message, details);
  }
}

export class NotFoundError extends AppError {
  constructor(resource: string) {
    super(404, 'NOT_FOUND', `${resource} not found`);
  }
}

export class ForbiddenError extends AppError {
  constructor(message = 'Insufficient permissions') {
    super(403, 'FORBIDDEN', message);
  }
}

export class ConflictError extends AppError {
  constructor(message: string) {
    super(409, 'CONFLICT', message);
  }
}

export class BusinessRuleError extends AppError {
  constructor(message: string, details?: unknown) {
    super(422, 'BUSINESS_RULE_VIOLATION', message, details);
  }
}
```

Fastify error handler catches `AppError` instances and formats the response. Unexpected errors return 500 with no internal details exposed.

## Logging

- Structured JSON via Pino (Fastify's built-in logger)
- Log levels: `fatal`, `error`, `warn`, `info`, `debug`, `trace`
- Production: `info` level minimum
- Every log entry includes: `requestId`, `userId` (if authenticated), `domain`, `action`
- **Never log:** PHN, patient names, passwords, tokens, H-Link credentials
- **Always log:** claim state transitions, auth events (login/logout/MFA), permission checks, API errors

## Testing Strategy

### Unit Tests (Vitest)
- Test service layer functions in isolation
- Mock repositories (inject mock DB functions)
- Located in `apps/api/src/domains/{name}/{name}.test.ts`
- Run: `pnpm --filter api test`

### Integration Tests (Vitest + Supertest)
- Test full API request/response cycle
- Use test database (separate from dev/prod)
- Fixtures in `apps/api/test/fixtures/`
- Located in `apps/api/test/integration/{domain}/`
- Run: `pnpm --filter api test:integration`

### Security Tests (Vitest + Supertest)
- **Mandatory for every domain. No domain is complete without passing security tests.**
- Located in `apps/api/test/security/{domain}/`
- Run: `pnpm --filter api test:security`
- Security tests run in CI alongside integration tests. A security test failure blocks merge.

### E2E Tests (Playwright)
- Test critical user flows through the browser
- Located in `apps/web/test/e2e/`
- Run: `pnpm --filter web test:e2e`

### Test Fixtures
Build a shared test fixture factory. Every integration test that needs a physician should use this:

```typescript
// apps/api/test/fixtures/createTestPhysician.ts
export async function createTestPhysician(overrides?: Partial<ProviderOverrides>) {
  const user = await createTestUser();
  const provider = await createProvider({ userId: user.id, ...defaults, ...overrides });
  const ba = await createBA({ providerId: provider.id });
  const location = await createLocation({ providerId: provider.id });
  return { user, provider, ba, location };
}
```

### Security Test Fixtures
Every security test suite uses two isolated physician contexts to verify cross-tenant isolation:

```typescript
// apps/api/test/fixtures/createSecurityPair.ts
export async function createSecurityPair() {
  const physician1 = await createTestPhysician();   // "our" physician
  const physician2 = await createTestPhysician();   // "other" physician (attacker perspective)
  const delegate = await createTestDelegate({
    physicianId: physician1.provider.id,
    permissions: ['CLAIM_VIEW'],                     // limited permissions
  });
  const unauthenticatedAgent = supertest(app);       // no session cookie
  return { physician1, physician2, delegate, unauthenticatedAgent };
}
```

## Automated Security Testing (MANDATORY)

**Every domain must include the following security test categories.** These are not optional. A domain is not complete until all applicable security test categories pass.

Security tests live in `apps/api/test/security/{domain}/` with one file per category:

```
test/security/{domain}/
├── {domain}.authn.security.ts         # Authentication enforcement
├── {domain}.authz.security.ts         # Authorization & permission checks
├── {domain}.scoping.security.ts       # Physician tenant isolation
├── {domain}.input.security.ts         # Input validation & injection
├── {domain}.leakage.security.ts       # PHI & data leakage prevention
└── {domain}.audit.security.ts         # Audit log verification
```

### Category 1: Authentication Enforcement (`authn.security.ts`)

Every endpoint must reject unauthenticated requests. Test **every route** in the domain:

```typescript
describe('Authentication Enforcement', () => {
  it('GET /api/v1/{domain}/{resource} returns 401 without session', async () => {
    const res = await unauthenticatedAgent.get('/api/v1/claims');
    expect(res.status).toBe(401);
    expect(res.body.data).toBeUndefined();  // No data leakage on 401
  });

  it('POST /api/v1/{domain}/{resource} returns 401 without session', async () => {
    const res = await unauthenticatedAgent.post('/api/v1/claims').send(validPayload);
    expect(res.status).toBe(401);
  });

  it('rejects expired session tokens', async () => { /* ... */ });
  it('rejects tampered session cookies', async () => { /* ... */ });
});
```

**Rule:** Enumerate every route registered in the domain's routes file. There must be one 401 test per route. No exceptions.

### Category 2: Authorization & Permissions (`authz.security.ts`)

Test that role-based and permission-based access controls are enforced:

```typescript
describe('Authorization', () => {
  // Delegate permission boundaries
  it('delegate WITHOUT CLAIM_CREATE permission cannot create claims', async () => {
    const res = await asDelegate(delegate, 'POST', '/api/v1/claims', validPayload);
    expect(res.status).toBe(403);
  });

  it('delegate WITH CLAIM_VIEW can list claims', async () => {
    const res = await asDelegate(delegate, 'GET', '/api/v1/claims');
    expect(res.status).toBe(200);
  });

  it('delegate sees only their physician context, not their own data', async () => {
    const res = await asDelegate(delegate, 'GET', '/api/v1/claims');
    res.body.data.forEach(claim => {
      expect(claim.providerId).toBe(physician1.provider.id);
    });
  });

  // Permission escalation prevention
  it('delegate cannot modify their own permissions', async () => { /* ... */ });
  it('delegate cannot grant themselves access to another physician', async () => { /* ... */ });
  
  // Internal endpoint protection
  it('internal endpoints reject external requests', async () => {
    const res = await asPhysician(physician1, 'POST', '/api/v1/internal/providers/claim-context');
    expect(res.status).toBe(403);  // or 404 to avoid leaking endpoint existence
  });
});
```

**Rule:** Test every permission key defined in the domain's FRD. Test both the positive case (has permission → succeeds) and the negative case (lacks permission → 403).

### Category 3: Physician Tenant Isolation (`scoping.security.ts`)

**This is the most critical security test category.** Every query that returns PHI must be tested to verify it never returns another physician's data. Use the `createSecurityPair` fixture.

```typescript
describe('Physician Tenant Isolation', () => {
  let pair: SecurityPair;

  beforeAll(async () => {
    pair = await createSecurityPair();
    // Create test data owned by physician1
    await createClaim({ providerId: pair.physician1.provider.id, ...claimData });
    // Create test data owned by physician2
    await createClaim({ providerId: pair.physician2.provider.id, ...claimData });
  });

  // LIST endpoints: physician only sees own data
  it('listing claims returns only the authenticated physician\'s claims', async () => {
    const res = await asPhysician(pair.physician1, 'GET', '/api/v1/claims');
    expect(res.body.data.length).toBeGreaterThan(0);
    res.body.data.forEach(claim => {
      expect(claim.providerId).toBe(pair.physician1.provider.id);
    });
  });

  // GET by ID: cannot access another physician's resource
  it('cannot retrieve another physician\'s claim by ID', async () => {
    const otherClaim = await getClaimOwnedBy(pair.physician2.provider.id);
    const res = await asPhysician(pair.physician1, 'GET', `/api/v1/claims/${otherClaim.id}`);
    expect(res.status).toBe(404);  // 404, not 403 (don't confirm existence)
  });

  // UPDATE: cannot modify another physician's resource
  it('cannot update another physician\'s claim', async () => {
    const otherClaim = await getClaimOwnedBy(pair.physician2.provider.id);
    const res = await asPhysician(pair.physician1, 'PUT', `/api/v1/claims/${otherClaim.id}`, updateData);
    expect(res.status).toBe(404);
  });

  // DELETE: cannot delete another physician's resource
  it('cannot delete another physician\'s patient', async () => {
    const otherPatient = await getPatientOwnedBy(pair.physician2.provider.id);
    const res = await asPhysician(pair.physician1, 'DELETE', `/api/v1/patients/${otherPatient.id}`);
    expect(res.status).toBe(404);
  });

  // SEARCH: results scoped to authenticated physician
  it('patient search never returns another physician\'s patients', async () => {
    const res = await asPhysician(pair.physician1, 'GET', '/api/v1/patients?search=Smith');
    res.body.data.forEach(patient => {
      expect(patient.providerId).toBe(pair.physician1.provider.id);
    });
  });

  // COUNT/AGGREGATE: no cross-tenant data in analytics
  it('analytics endpoints only aggregate the authenticated physician\'s data', async () => {
    const res = await asPhysician(pair.physician1, 'GET', '/api/v1/analytics/revenue?period=this_month');
    // Verify the total matches only physician1's claims, not physician2's
  });
});
```

**Rule:** For every table that contains a `provider_id` column, there must be a tenant isolation test for every query path (list, get-by-id, update, delete, search, aggregate). The test must create data for BOTH physicians and verify that physician1 NEVER sees physician2's data. Return 404 (not 403) when accessing another physician's resource — do not confirm the resource exists.

### Category 4: Input Validation & Injection Prevention (`input.security.ts`)

Test that malicious input is rejected at the Zod schema layer and cannot reach the database:

```typescript
describe('Input Validation & Injection', () => {
  // SQL injection attempts
  it('rejects SQL injection in string fields', async () => {
    const payloads = [
      "'; DROP TABLE claims; --",
      "1' OR '1'='1",
      "1; SELECT * FROM users --",
      "' UNION SELECT * FROM providers --",
    ];
    for (const payload of payloads) {
      const res = await asPhysician(physician1, 'POST', '/api/v1/claims', {
        ...validPayload,
        healthServiceCode: payload,
      });
      expect(res.status).toBe(400);  // Rejected by Zod, never reaches DB
    }
  });

  // XSS payloads
  it('rejects XSS payloads in text fields', async () => {
    const payloads = [
      '<script>alert("xss")</script>',
      '<img src=x onerror=alert(1)>',
      'javascript:alert(1)',
    ];
    for (const payload of payloads) {
      const res = await asPhysician(physician1, 'POST', '/api/v1/patients', {
        ...validPatient,
        firstName: payload,
      });
      // Either rejected (400) or stored safely (no script execution on retrieval)
      if (res.status === 201) {
        const retrieved = await asPhysician(physician1, 'GET', `/api/v1/patients/${res.body.data.id}`);
        expect(retrieved.body.data.firstName).not.toContain('<script>');
      }
    }
  });

  // Type coercion attacks
  it('rejects wrong types in request body', async () => {
    const res = await asPhysician(physician1, 'POST', '/api/v1/claims', {
      ...validPayload,
      dateOfService: 12345,           // number instead of string
    });
    expect(res.status).toBe(400);
  });

  it('rejects negative values for fee amounts', async () => { /* ... */ });
  it('rejects oversized payloads (>1MB)', async () => { /* ... */ });
  it('rejects path traversal in file upload filenames', async () => { /* ... */ });

  // PHN validation
  it('rejects PHN with invalid Luhn check digit', async () => { /* ... */ });
  it('rejects PHN with non-numeric characters', async () => { /* ... */ });

  // UUID parameter tampering
  it('rejects non-UUID path parameters', async () => {
    const res = await asPhysician(physician1, 'GET', '/api/v1/claims/not-a-uuid');
    expect(res.status).toBe(400);
  });
});
```

**Rule:** Every domain must test SQL injection payloads against all string input fields, XSS payloads against all text fields that render in the UI, type coercion against all non-string fields, and UUID format validation against all ID parameters. Drizzle's parameterized queries prevent SQL injection at the ORM level, but these tests verify the Zod layer catches it first.

### Category 5: PHI & Data Leakage Prevention (`leakage.security.ts`)

Test that PHI is never exposed in error responses, headers, or logs:

```typescript
describe('PHI Leakage Prevention', () => {
  // Error responses must not contain PHI
  it('validation error does not echo PHN back to client', async () => {
    const res = await asPhysician(physician1, 'POST', '/api/v1/patients', {
      ...validPatient,
      phn: '999999999',  // invalid Luhn
    });
    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).not.toContain('999999999');
  });

  it('404 responses do not reveal resource details', async () => {
    const res = await asPhysician(physician1, 'GET', `/api/v1/patients/${nonExistentUuid}`);
    expect(res.status).toBe(404);
    expect(res.body.error.message).not.toContain('patient');  // Generic "not found"
    expect(res.body.error.message).not.toContain(nonExistentUuid);
  });

  it('500 errors do not expose stack traces or internal details', async () => {
    // Trigger an internal error (e.g., invalid DB state)
    const res = await triggerInternalError();
    expect(res.status).toBe(500);
    expect(res.body.error.message).toBe('Internal server error');
    expect(res.body.error).not.toHaveProperty('stack');
    expect(JSON.stringify(res.body)).not.toMatch(/postgres|drizzle|sql/i);
  });

  // Response headers must not leak internals
  it('responses do not contain server version headers', async () => {
    const res = await asPhysician(physician1, 'GET', '/api/v1/claims');
    expect(res.headers).not.toHaveProperty('x-powered-by');
    expect(res.headers['server']).toBeUndefined();
  });

  // PHN masking in any text output
  it('audit log entries mask PHN', async () => {
    await createPatientWithPhn('123456789');
    const auditLogs = await getRecentAuditLogs();
    const logString = JSON.stringify(auditLogs);
    expect(logString).not.toContain('123456789');
    expect(logString).toContain('123******');  // Masked format
  });

  // Email content safety
  it('notification emails do not contain PHI', async () => {
    // Trigger a claim rejection notification
    await rejectClaim(testClaim.id);
    const sentEmail = await getLastSentEmail();
    expect(sentEmail.body).not.toContain(testPatient.phn);
    expect(sentEmail.body).not.toContain(testPatient.firstName);
    expect(sentEmail.body).toContain('meritum.ca/claims/');  // Link, not data
  });

  // Report download authentication
  it('report download links require authentication', async () => {
    const report = await generateReport(physician1);
    const res = await unauthenticatedAgent.get(report.downloadUrl);
    expect(res.status).toBe(401);
  });

  it('report download links reject other physicians', async () => {
    const report = await generateReport(physician1);
    const res = await asPhysician(physician2, 'GET', report.downloadUrl);
    expect(res.status).toBe(404);
  });
});
```

**Rule:** Every domain that handles PHI must verify: (1) error responses never echo PHI, (2) 500 errors expose no internals, (3) server headers are stripped, (4) audit logs mask PHN, (5) email content contains links not data, (6) file downloads require authentication and physician scoping.

### Category 6: Audit Trail Verification (`audit.security.ts`)

Test that security-relevant actions produce audit records:

```typescript
describe('Audit Trail', () => {
  it('claim state change produces audit record', async () => {
    const claim = await createClaim(physician1);
    await submitClaim(physician1, claim.id);
    const audit = await getAuditLog({ resourceType: 'claim', resourceId: claim.id });
    expect(audit).toContainEqual(expect.objectContaining({
      action: 'CLAIM_STATE_CHANGE',
      oldState: 'VALIDATED',
      newState: 'QUEUED',
      actorId: physician1.user.id,
    }));
  });

  it('failed login attempt produces audit record', async () => { /* ... */ });
  it('permission change produces audit record', async () => { /* ... */ });
  it('delegate access revocation produces audit record', async () => { /* ... */ });
  it('data export request produces audit record', async () => { /* ... */ });
  it('account deletion request produces audit record', async () => { /* ... */ });

  // Audit log integrity
  it('audit logs cannot be modified via API', async () => {
    // No PUT/DELETE endpoints for audit logs
  });

  it('audit logs cannot be deleted by the physician', async () => { /* ... */ });
});
```

**Rule:** Every state change on claims, providers, patients, delegates, and subscriptions must produce an audit record. Auth events (login, logout, MFA, failed attempts) must be logged. The audit log must be append-only with no modification or deletion API.

### Security Test Coverage Requirements

Before a domain is considered complete, verify:

| Category | Minimum Tests | Applies To |
|----------|--------------|------------|
| Authentication (authn) | 1 per route | All domains |
| Authorization (authz) | 1 per permission key | Domains with delegate access |
| Tenant isolation (scoping) | 1 per query path (list/get/update/delete/search) | All domains with provider_id |
| Input validation (input) | SQL injection + XSS + type coercion per input field | All domains with user input |
| Leakage prevention (leakage) | Error response + header + log checks | All domains handling PHI |
| Audit trail (audit) | 1 per state-changing action | All domains with state changes |

## Environment Variables

```env
# Database
DATABASE_URL=postgresql://user:pass@host:port/meritum?sslmode=require

# Auth
SESSION_SECRET=<random-64-bytes-hex>
ARGON2_MEMORY=19456
ARGON2_ITERATIONS=2

# Stripe
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_STANDARD_MONTHLY=price_...
STRIPE_PRICE_STANDARD_ANNUAL=price_...
STRIPE_PRICE_EARLY_BIRD=price_...

# Postmark
POSTMARK_SERVER_TOKEN=...
POSTMARK_FROM_EMAIL=notifications@meritum.ca

# DigitalOcean Spaces
SPACES_ENDPOINT=tor1.digitaloceanspaces.com
SPACES_BUCKET=meritum-files
SPACES_ACCESS_KEY=...
SPACES_SECRET_KEY=...

# H-Link (AHCIP submission)
HLINK_ENDPOINT=<AHCIP H-Link endpoint>
HLINK_SUBMITTER_PREFIX=<Meritum accredited submitter prefix>
HLINK_CREDENTIAL_ID=<stored securely, never in DB>
HLINK_CREDENTIAL_SECRET=<stored securely, never in DB>

# App
NODE_ENV=production
API_PORT=3001
API_HOST=0.0.0.0
CORS_ORIGIN=https://meritum.ca
LOG_LEVEL=info
```

## Domain Build Order (Critical Path)

Build domains in this order. Each domain's FRD is in `docs/frd/`.

1. **Domain 1: Identity & Access** — Foundation. Auth, sessions, RBAC.
2. **Domain 12: Platform Operations** — Stripe subscription (needed before onboarding).
3. **Domain 2: Reference Data** — SOMB codes, governing rules, modifiers. Consumed by everything.
4. **Domain 5: Provider Management** — Physician profiles, BAs, locations, delegates. Produces provider context.
5. **Domain 6: Patient Registry** — Patient demographics, PHN validation, CSV import.
6. **Domain 11: Onboarding** — First-run wizard. Writes to Domains 5 and 6.
7. **Domain 9: Notification Service** — Event bus, in-app + email delivery. Required by Domains 4+.
8. **Domain 4.0: Claim Lifecycle Core** — State machine, validation engine, batch assembly.
9. **Domain 4.1: AHCIP Pathway** — H-Link submission, assessment retrieval, PCPCM routing.
10. **Domain 4.2: WCB Pathway** — WCB forms, timing tiers, OIS appendix.
11. **Domain 7: Intelligence Engine** — AI Coach rules engine, LLM integration, learning loop.
12. **Domain 8: Analytics & Reporting** — Dashboards, reports, exports.
13. **Domain 10: Mobile Companion** — Responsive UI, ED shifts, favourites.
14. **Domain 13: Support System** — Help centre, email support, ticket tracking.

## Working With This Codebase

### Build-Test-Fix Loop (MANDATORY)

**Never move to the next file or task until the current one passes all tests.** After writing any code, immediately follow this loop:

```
1. WRITE code (repository, service, handler, route, or test file)
2. RUN relevant tests:
   - After writing service:     pnpm --filter api vitest run src/domains/{name}/{name}.test.ts
   - After writing routes:      pnpm --filter api vitest run test/integration/{domain}/
   - After writing sec tests:   pnpm --filter api vitest run test/security/{domain}/
   - After writing everything:  pnpm --filter api test
3. READ test output. If failures exist:
   a. Identify the root cause from the error message and stack trace
   b. Fix the code (not the test, unless the test itself is wrong)
   c. Re-run ONLY the failing test file (faster feedback)
   d. Repeat until green
4. MOVE to the next file only when all tests pass
```

**Context window management during fix loops:**
- Run only the specific failing test file, not the full suite, to minimize output
- Use `--reporter=verbose` only when you need detailed failure info
- After fixing, run the specific file first, then the full domain suite to check for regressions
- If a fix loop exceeds 3 iterations on the same failure, stop and add a `// TODO: FAILING —` comment with the error details, then move on. The task runner will flag this.

### When Invoked by the Task Runner

When your prompt starts with `[TASK]`, you are being invoked by the automated task runner. Follow these rules:

1. Read the task description carefully — it specifies exactly which files to create/modify
2. Read only the FRD sections referenced in the task (not the whole FRD)
3. Complete the build-test-fix loop for every file
4. After all tests pass, output exactly this on a new line: `[TASK_COMPLETE]`
5. If tests fail after 5 fix attempts, output: `[TASK_BLOCKED] reason: <one-line description>`
6. Do not ask questions — make reasonable decisions based on CLAUDE.md and the FRD

### Standard Development Workflow (Interactive)

When given a task interactively:
1. Identify which domain(s) are affected
2. Read the FRD for that domain in `docs/frd/` if you need business context
3. Follow the domain module structure exactly
4. Add Zod schemas in `packages/shared` (not in the API)
5. Write the repository, service, handler, and routes in that order
6. **Run tests after each file. Fix failures before moving to the next file.**
7. **Add security tests for the domain (all 6 categories). This is not optional.**
8. Run all tests to ensure nothing breaks: `pnpm test && pnpm test:security`

### Domain Completion Checklist

A domain is **not complete** until all of the following exist and pass:

- [ ] Drizzle schema in `packages/shared/src/schemas/db/`
- [ ] Zod validation schemas in `packages/shared/src/schemas/`
- [ ] Repository layer with physician scoping on every PHI query
- [ ] Service layer with business logic
- [ ] Handler layer (thin)
- [ ] Routes with Zod schema validation and permission guards
- [ ] Unit tests for service layer
- [ ] Integration tests for API endpoints
- [ ] Security: `authn.security.ts` — 401 test for every route
- [ ] Security: `authz.security.ts` — permission tests for every guarded action
- [ ] Security: `scoping.security.ts` — tenant isolation for every query path
- [ ] Security: `input.security.ts` — injection and validation tests
- [ ] Security: `leakage.security.ts` — PHI leakage prevention
- [ ] Security: `audit.security.ts` — audit record verification for state changes

**Do not:**
- Skip the service layer and put logic in handlers
- Put Zod schemas in the API instead of the shared package
- Use raw SQL without going through Drizzle
- Access another domain's tables directly — use the domain's service or internal API
- Return detailed error messages that could leak PHI or system internals
- Log PHN, patient names, or credentials
- Make Stripe API calls outside the platform domain
- Send PHI in emails
- **Mark a domain as complete without all 6 security test categories passing**
- **Skip tenant isolation tests — these are the most critical security control in the platform**
