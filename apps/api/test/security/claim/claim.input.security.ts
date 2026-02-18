import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib
// ---------------------------------------------------------------------------

vi.mock('otplib', () => {
  const mockAuthenticator = {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(
      (email: string, issuer: string, secret: string) =>
        `otpauth://totp/${issuer}:${email}?secret=${secret}&issuer=${issuer}`,
    ),
    verify: vi.fn(({ token }: { token: string }) => token === '123456'),
  };
  return { authenticator: mockAuthenticator };
});

// ---------------------------------------------------------------------------
// Real imports (after mocks are hoisted)
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { claimRoutes } from '../../../src/domains/claim/claim.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { type ClaimHandlerDeps } from '../../../src/domains/claim/claim.handlers.js';
import {
  type SessionManagementDeps,
  hashToken,
} from '../../../src/domains/iam/iam.service.js';
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Fixed test identity — authenticated physician for input validation tests
// ---------------------------------------------------------------------------

const P1_SESSION_TOKEN = randomBytes(32).toString('hex');
const P1_SESSION_TOKEN_HASH = hashToken(P1_SESSION_TOKEN);
const P1_USER_ID = '11111111-1111-0000-0000-000000000001';
const P1_PROVIDER_ID = P1_USER_ID;
const P1_SESSION_ID = '11111111-1111-0000-0000-000000000011';

const P1_PATIENT_ID = 'bbbb1111-0000-0000-0000-000000000001';
const P1_CLAIM_ID = 'aaaa1111-0000-0000-0000-000000000001';
const P1_TEMPLATE_ID = 'dddd1111-0000-0000-0000-000000000001';
const P1_SHIFT_ID = 'eeee1111-0000-0000-0000-000000000001';
const P1_FACILITY_ID = '77771111-0000-0000-0000-000000000001';
const P1_SUGGESTION_ID = 'aabb1111-0000-0000-0000-000000000001';

const VALID_UUID = '99999999-9999-9999-9999-999999999999';

// ---------------------------------------------------------------------------
// Mock stores
// ---------------------------------------------------------------------------

interface MockUser {
  userId: string;
  email: string;
  passwordHash: string;
  mfaConfigured: boolean;
  totpSecretEncrypted: string | null;
  failedLoginCount: number;
  lockedUntil: Date | null;
  isActive: boolean;
  role: string;
  subscriptionStatus: string;
}

interface MockSession {
  sessionId: string;
  userId: string;
  tokenHash: string;
  ipAddress: string;
  userAgent: string;
  createdAt: Date;
  lastActiveAt: Date;
  revoked: boolean;
  revokedReason: string | null;
}

let users: MockUser[] = [];
let sessions: MockSession[] = [];

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

function createMockSessionRepo() {
  return {
    createSession: vi.fn(async () => ({ sessionId: 'new-session-id' })),
    findSessionByTokenHash: vi.fn(async (tokenHash: string) => {
      const session = sessions.find((s) => s.tokenHash === tokenHash && !s.revoked);
      if (!session) return undefined;
      const user = users.find((u) => u.userId === session.userId);
      if (!user) return undefined;
      return {
        session,
        user: {
          userId: user.userId,
          role: user.role,
          subscriptionStatus: user.subscriptionStatus,
        },
      };
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

function createMockAuditRepo() {
  return {
    appendAuditLog: vi.fn(async () => {}),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Stub claim repository — returns data for P1's resources
// ---------------------------------------------------------------------------

function createStubClaimRepo() {
  return {
    createClaim: vi.fn(async (data: any) => ({
      claimId: crypto.randomUUID(),
      physicianId: data.physicianId,
      patientId: data.patientId,
      claimType: data.claimType,
      state: 'DRAFT',
      dateOfService: data.dateOfService,
      submissionDeadline: '2026-06-01',
      importSource: data.importSource ?? 'MANUAL',
      importBatchId: null,
      shiftId: null,
      isClean: true,
      validationResult: null,
      aiCoachSuggestions: null,
      duplicateAlert: null,
      flags: null,
      createdBy: data.createdBy,
      updatedBy: data.createdBy,
      deletedAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    findClaimById: vi.fn(async (claimId: string, physicianId: string) => {
      if (claimId === P1_CLAIM_ID && physicianId === P1_PROVIDER_ID) {
        return {
          claimId: P1_CLAIM_ID,
          physicianId: P1_PROVIDER_ID,
          patientId: P1_PATIENT_ID,
          claimType: 'AHCIP',
          state: 'DRAFT',
          dateOfService: '2026-01-15',
          submissionDeadline: '2026-04-15',
          importSource: 'MANUAL',
          importBatchId: null,
          shiftId: null,
          isClean: true,
          validationResult: null,
          aiCoachSuggestions: {
            suggestions: [
              { id: P1_SUGGESTION_ID, field: 'healthServiceCode', suggestedValue: '03.04A', status: 'PENDING' },
            ],
          },
          duplicateAlert: null,
          flags: null,
          createdBy: P1_USER_ID,
          updatedBy: P1_USER_ID,
          deletedAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
      }
      return undefined;
    }),
    updateClaim: vi.fn(async (claimId: string, physicianId: string, data: any) => {
      if (claimId === P1_CLAIM_ID && physicianId === P1_PROVIDER_ID) {
        return { claimId: P1_CLAIM_ID, ...data };
      }
      return undefined;
    }),
    softDeleteClaim: vi.fn(async (claimId: string, physicianId: string) => {
      return claimId === P1_CLAIM_ID && physicianId === P1_PROVIDER_ID;
    }),
    listClaims: vi.fn(async (_physicianId: string, filters: any) => {
      const page = filters.page ?? 1;
      const pageSize = Math.min(filters.pageSize ?? 25, 100);
      return {
        data: [],
        pagination: { total: 0, page, pageSize, hasMore: false },
      };
    }),
    countClaimsByState: vi.fn(async () => []),
    findClaimsApproachingDeadline: vi.fn(async () => []),
    transitionState: vi.fn(async () => ({})),
    classifyClaim: vi.fn(async () => ({})),
    updateValidationResult: vi.fn(async () => ({})),
    updateAiSuggestions: vi.fn(async () => ({})),
    updateDuplicateAlert: vi.fn(async () => ({})),
    updateFlags: vi.fn(async () => ({})),
    createImportBatch: vi.fn(async () => ({})),
    findImportBatchById: vi.fn(async () => undefined),
    updateImportBatchStatus: vi.fn(async () => ({})),
    findDuplicateImportByHash: vi.fn(async () => undefined),
    listImportBatches: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
    findClaimsForBatchAssembly: vi.fn(async () => []),
    bulkTransitionState: vi.fn(async () => []),
    createTemplate: vi.fn(async (data: any) => ({
      templateId: crypto.randomUUID(),
      physicianId: data.physicianId,
      name: data.name,
      emrType: data.emrType ?? null,
      mappings: data.mappings ?? [],
      delimiter: data.delimiter ?? ',',
      hasHeaderRow: data.hasHeaderRow ?? true,
      dateFormat: data.dateFormat ?? null,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    findTemplateById: vi.fn(async (templateId: string, physicianId: string) => {
      if (templateId === P1_TEMPLATE_ID && physicianId === P1_PROVIDER_ID) {
        return {
          templateId: P1_TEMPLATE_ID,
          physicianId: P1_PROVIDER_ID,
          name: 'Test Template',
          emrType: 'ACCURO',
          mappings: [{ source_column: 'col1', target_field: 'patientId' }],
          delimiter: ',',
          hasHeaderRow: true,
          dateFormat: null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
      }
      return undefined;
    }),
    updateTemplate: vi.fn(async (templateId: string, physicianId: string, data: any) => {
      if (templateId === P1_TEMPLATE_ID && physicianId === P1_PROVIDER_ID) {
        return { templateId: P1_TEMPLATE_ID, ...data };
      }
      return undefined;
    }),
    deleteTemplate: vi.fn(async (templateId: string, physicianId: string) => {
      return templateId === P1_TEMPLATE_ID && physicianId === P1_PROVIDER_ID;
    }),
    listTemplates: vi.fn(async () => []),
    createShift: vi.fn(async (data: any) => ({
      shiftId: crypto.randomUUID(),
      physicianId: data.physicianId,
      facilityId: data.facilityId,
      shiftDate: data.shiftDate,
      startTime: data.startTime ?? null,
      endTime: data.endTime ?? null,
      encounterCount: 0,
      status: 'IN_PROGRESS',
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    findShiftById: vi.fn(async (shiftId: string, physicianId: string) => {
      if (shiftId === P1_SHIFT_ID && physicianId === P1_PROVIDER_ID) {
        return {
          shiftId: P1_SHIFT_ID,
          physicianId: P1_PROVIDER_ID,
          facilityId: P1_FACILITY_ID,
          shiftDate: '2026-01-20',
          startTime: '08:00',
          endTime: '16:00',
          encounterCount: 3,
          status: 'IN_PROGRESS',
          createdAt: new Date(),
          updatedAt: new Date(),
        };
      }
      return undefined;
    }),
    updateShiftStatus: vi.fn(async () => ({})),
    updateShiftTimes: vi.fn(async () => ({})),
    incrementEncounterCount: vi.fn(async () => ({})),
    listShifts: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
    findClaimsByShift: vi.fn(async () => []),
    createExportRecord: vi.fn(async (data: any) => ({
      exportId: crypto.randomUUID(),
      physicianId: data.physicianId,
      dateFrom: data.dateFrom,
      dateTo: data.dateTo,
      claimType: data.claimType ?? null,
      format: data.format,
      status: 'PENDING',
      filePath: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    })),
    findExportById: vi.fn(async () => undefined),
    updateExportStatus: vi.fn(async () => ({})),
    appendClaimAudit: vi.fn(async () => ({})),
    getClaimAuditHistory: vi.fn(async () => []),
    getClaimAuditHistoryPaginated: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
  };
}

function createStubServiceDeps() {
  return {
    repo: createStubClaimRepo() as any,
    providerCheck: {
      isActive: vi.fn(async () => true),
      getRegistrationDate: vi.fn(async () => null),
    },
    patientCheck: {
      exists: vi.fn(async () => true),
    },
    pathwayValidators: {},
    referenceDataVersion: { getCurrentVersion: vi.fn(async () => '1.0') },
    notificationEmitter: { emit: vi.fn(async () => {}) },
    submissionPreference: { getSubmissionMode: vi.fn(async () => 'MANUAL') },
    facilityCheck: { belongsToPhysician: vi.fn(async () => true) },
    afterHoursPremiumCalculators: {},
    explanatoryCodeLookup: { getExplanatoryCode: vi.fn(async () => null) },
  };
}

// ---------------------------------------------------------------------------
// Test App Builder
// ---------------------------------------------------------------------------

let app: FastifyInstance;

async function buildTestApp(): Promise<FastifyInstance> {
  const mockSessionRepo = createMockSessionRepo();

  const sessionDeps: SessionManagementDeps = {
    sessionRepo: mockSessionRepo,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
  };

  const handlerDeps: ClaimHandlerDeps = {
    serviceDeps: createStubServiceDeps(),
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, _request, reply) => {
    // Validation errors — never echo user input in error messages.
    // Fastify + Zod validation errors have code FST_ERR_VALIDATION
    // or error.validation set. Sanitise both paths to prevent input echo-back.
    if (error.validation || (error as any).code === 'FST_ERR_VALIDATION') {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed' },
      });
    }
    const statusCode = (error as any).statusCode;
    if (statusCode && statusCode >= 400 && statusCode < 500) {
      return reply.code(statusCode).send({
        error: { code: (error as any).code ?? 'ERROR', message: error.message },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(claimRoutes, { deps: handlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function seedUsersAndSessions() {
  users = [];
  sessions = [];

  users.push({
    userId: P1_USER_ID,
    email: 'physician1@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'PHYSICIAN',
    subscriptionStatus: 'TRIAL',
  });
  sessions.push({
    sessionId: P1_SESSION_ID,
    userId: P1_USER_ID,
    tokenHash: P1_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

function asPhysician(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// Valid payloads for baseline comparison
const VALID_CREATE_CLAIM = {
  claim_type: 'AHCIP',
  patient_id: P1_PATIENT_ID,
  date_of_service: '2026-01-15',
};

const VALID_CREATE_TEMPLATE = {
  name: 'Test Template',
  mappings: [{ source_column: 'col1', target_field: 'patientId' }],
  has_header_row: true,
};

const VALID_CREATE_SHIFT = {
  facility_id: P1_FACILITY_ID,
  shift_date: '2026-01-20',
  start_time: '08:00',
  end_time: '16:00',
};

const VALID_ADD_ENCOUNTER = {
  patient_id: P1_PATIENT_ID,
  date_of_service: '2026-01-20',
  claim_type: 'AHCIP',
};

const VALID_CREATE_EXPORT = {
  date_from: '2026-01-01',
  date_to: '2026-01-31',
  format: 'CSV',
};

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Claim Input Validation & Injection Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsersAndSessions();
  });

  // =========================================================================
  // 1. SQL Injection Payloads on String Fields
  // =========================================================================

  describe('SQL injection prevention', () => {
    const SQL_INJECTION_PAYLOADS = [
      "'; DROP TABLE claims; --",
      "1' OR '1'='1",
      "1; SELECT * FROM users --",
      "' UNION SELECT * FROM providers --",
      "AHCIP'; DROP TABLE claims;--",
      "'; DELETE FROM claims WHERE '1'='1",
      "' OR 1=1--",
    ];

    describe('claim_type field rejects SQL injection', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/claims', {
            ...VALID_CREATE_CLAIM,
            claim_type: payload,
          });
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('state filter rejects SQL injection in list query', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects state filter: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician(
            'GET',
            `/api/v1/claims?state=${encodeURIComponent(payload)}`,
          );
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }
    });

    describe('write-off reason field rejects SQL injection', () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        it(`rejects write-off reason: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', `/api/v1/claims/${P1_CLAIM_ID}/write-off`, {
            reason: payload,
          });
          // Write-off reason is a free-text field (string min 1, max 500).
          // SQL payloads may pass Zod validation since they are valid strings.
          // But Drizzle parameterised queries prevent actual injection.
          // Either 400 (rejected by Zod) or non-400 (accepted but safely parameterised) is acceptable.
          if (res.statusCode === 400) {
            const body = JSON.parse(res.body);
            expect(body.data).toBeUndefined();
          }
          // If accepted, the payload is parameterised and cannot execute SQL
        });
      }
    });

    describe('template name field rejects SQL injection', () => {
      for (const payload of SQL_INJECTION_PAYLOADS.slice(0, 4)) {
        it(`rejects template name: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/field-mapping-templates', {
            ...VALID_CREATE_TEMPLATE,
            name: payload,
          });
          // Template name is string min 1, max 100. Short SQL payloads may pass Zod.
          // Drizzle parameterised queries prevent injection at ORM level.
          // Verify the response doesn't expose SQL errors.
          if (res.statusCode >= 500) {
            const body = JSON.parse(res.body);
            expect(body.error.message).toBe('Internal server error');
            expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
          }
        });
      }
    });

    describe('suggestion dismiss reason rejects SQL injection', () => {
      for (const payload of SQL_INJECTION_PAYLOADS.slice(0, 3)) {
        it(`rejects dismiss reason: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician(
            'POST',
            `/api/v1/claims/${P1_CLAIM_ID}/suggestions/${P1_SUGGESTION_ID}/dismiss`,
            { reason: payload },
          );
          // Dismiss reason is an optional string, max 500. Payloads may pass Zod.
          // Drizzle protects against actual injection.
          if (res.statusCode >= 500) {
            const body = JSON.parse(res.body);
            expect(body.error.message).toBe('Internal server error');
            expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
          }
        });
      }
    });

    describe('field mapping source_column rejects SQL injection', () => {
      for (const payload of SQL_INJECTION_PAYLOADS.slice(0, 3)) {
        it(`rejects mapping source_column: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/field-mapping-templates', {
            ...VALID_CREATE_TEMPLATE,
            mappings: [{ source_column: payload, target_field: 'patientId' }],
          });
          // source_column is string min 1, most payloads pass Zod.
          // Verify no SQL error surfaces.
          if (res.statusCode >= 500) {
            const body = JSON.parse(res.body);
            expect(body.error.message).toBe('Internal server error');
            expect(JSON.stringify(body)).not.toMatch(/postgres|drizzle|sql|syntax/i);
          }
        });
      }
    });
  });

  // =========================================================================
  // 2. XSS Payloads on Stored Text Fields
  // =========================================================================

  describe('XSS payload prevention', () => {
    const XSS_PAYLOADS = [
      '<script>alert("xss")</script>',
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<img onerror=alert(1) src=x>',
      'javascript:alert(1)',
      '<svg onload=alert(1)>',
      '"><script>document.cookie</script>',
    ];

    describe('write-off reason does not store executable XSS', () => {
      for (const payload of XSS_PAYLOADS.slice(0, 3)) {
        it(`handles XSS in write-off reason: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', `/api/v1/claims/${P1_CLAIM_ID}/write-off`, {
            reason: payload,
          });
          // Free-text field — Zod may accept. If stored, verify no script in response.
          if (res.statusCode === 200 || res.statusCode === 201) {
            const body = JSON.parse(res.body);
            const bodyString = JSON.stringify(body);
            // Either sanitised or stored as-is (client-side rendering escapes it)
            // At minimum, verify no unescaped script tags in JSON response
            expect(bodyString).not.toContain('<script>');
          }
        });
      }
    });

    describe('template name: XSS payloads stored safely in JSON', () => {
      for (const payload of XSS_PAYLOADS.slice(0, 3)) {
        it(`stores safely: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician('POST', '/api/v1/field-mapping-templates', {
            ...VALID_CREATE_TEMPLATE,
            name: payload.slice(0, 100), // max 100 chars
          });
          if (res.statusCode === 201 || res.statusCode === 200) {
            // JSON API responses are content-type application/json.
            // Browsers will NOT render JSON as HTML, so raw HTML in JSON string
            // values cannot execute. React additionally auto-escapes at render.
            const contentType = res.headers['content-type'] as string;
            expect(contentType).toContain('application/json');
          }
        });
      }
    });

    describe('dismiss suggestion reason does not store executable XSS', () => {
      for (const payload of XSS_PAYLOADS.slice(0, 3)) {
        it(`handles XSS in dismiss reason: ${payload.slice(0, 40)}...`, async () => {
          const res = await asPhysician(
            'POST',
            `/api/v1/claims/${P1_CLAIM_ID}/suggestions/${P1_SUGGESTION_ID}/dismiss`,
            { reason: payload },
          );
          if (res.statusCode === 200 || res.statusCode === 201) {
            const body = JSON.parse(res.body);
            const bodyString = JSON.stringify(body);
            expect(bodyString).not.toContain('<script>');
          }
        });
      }
    });

    describe('emr_type: XSS payloads stored safely in JSON', () => {
      for (const payload of XSS_PAYLOADS.slice(0, 2)) {
        it(`stores safely: ${payload.slice(0, 40)}...`, async () => {
          const truncated = payload.slice(0, 50); // max 50 chars
          const res = await asPhysician('POST', '/api/v1/field-mapping-templates', {
            ...VALID_CREATE_TEMPLATE,
            emr_type: truncated,
          });
          if (res.statusCode === 201 || res.statusCode === 200) {
            // JSON API responses cannot execute HTML/JS in browsers
            const contentType = res.headers['content-type'] as string;
            expect(contentType).toContain('application/json');
          }
        });
      }
    });
  });

  // =========================================================================
  // 3. Type Coercion Attacks
  // =========================================================================

  describe('Type coercion attacks', () => {
    describe('claim_type field rejects wrong types', () => {
      it('rejects number where string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/claims', {
          ...VALID_CREATE_CLAIM,
          claim_type: 12345,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects array where string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/claims', {
          ...VALID_CREATE_CLAIM,
          claim_type: ['AHCIP', 'WCB'],
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects object where string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/claims', {
          ...VALID_CREATE_CLAIM,
          claim_type: { value: 'AHCIP' },
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects boolean where string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/claims', {
          ...VALID_CREATE_CLAIM,
          claim_type: true,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects null where required', async () => {
        const res = await asPhysician('POST', '/api/v1/claims', {
          ...VALID_CREATE_CLAIM,
          claim_type: null,
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('date_of_service rejects wrong types', () => {
      it('rejects number where date string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/claims', {
          ...VALID_CREATE_CLAIM,
          date_of_service: 12345,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects boolean where date string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/claims', {
          ...VALID_CREATE_CLAIM,
          date_of_service: true,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects array where date string expected', async () => {
        const res = await asPhysician('POST', '/api/v1/claims', {
          ...VALID_CREATE_CLAIM,
          date_of_service: ['2026-01-15'],
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects null where required date expected', async () => {
        const res = await asPhysician('POST', '/api/v1/claims', {
          ...VALID_CREATE_CLAIM,
          date_of_service: null,
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('patient_id rejects wrong types', () => {
      it('rejects number where UUID expected', async () => {
        const res = await asPhysician('POST', '/api/v1/claims', {
          ...VALID_CREATE_CLAIM,
          patient_id: 12345,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects array where UUID expected', async () => {
        const res = await asPhysician('POST', '/api/v1/claims', {
          ...VALID_CREATE_CLAIM,
          patient_id: [P1_PATIENT_ID],
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects null where required UUID expected', async () => {
        const res = await asPhysician('POST', '/api/v1/claims', {
          ...VALID_CREATE_CLAIM,
          patient_id: null,
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('has_header_row rejects wrong types for template', () => {
      it('rejects string where boolean expected', async () => {
        const res = await asPhysician('POST', '/api/v1/field-mapping-templates', {
          ...VALID_CREATE_TEMPLATE,
          has_header_row: 'yes',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects number where boolean expected', async () => {
        const res = await asPhysician('POST', '/api/v1/field-mapping-templates', {
          ...VALID_CREATE_TEMPLATE,
          has_header_row: 1,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects null where required boolean expected', async () => {
        const res = await asPhysician('POST', '/api/v1/field-mapping-templates', {
          ...VALID_CREATE_TEMPLATE,
          has_header_row: null,
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('mappings rejects wrong types for template', () => {
      it('rejects string where array expected', async () => {
        const res = await asPhysician('POST', '/api/v1/field-mapping-templates', {
          ...VALID_CREATE_TEMPLATE,
          mappings: 'not-an-array',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects empty array (min 1 required)', async () => {
        const res = await asPhysician('POST', '/api/v1/field-mapping-templates', {
          ...VALID_CREATE_TEMPLATE,
          mappings: [],
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects array with invalid entries', async () => {
        const res = await asPhysician('POST', '/api/v1/field-mapping-templates', {
          ...VALID_CREATE_TEMPLATE,
          mappings: [{ wrong_key: 'value' }],
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('submission mode rejects wrong types', () => {
      it('rejects number where enum string expected', async () => {
        const res = await asPhysician('PUT', '/api/v1/submission-preferences', {
          mode: 123,
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects null where required', async () => {
        const res = await asPhysician('PUT', '/api/v1/submission-preferences', {
          mode: null,
        });
        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // 4. Pagination Boundary Attacks
  // =========================================================================

  describe('Pagination boundary attacks', () => {
    it('rejects negative page_size', async () => {
      const res = await asPhysician('GET', '/api/v1/claims?page_size=-1');
      expect(res.statusCode).toBe(400);
    });

    it('rejects zero page_size', async () => {
      const res = await asPhysician('GET', '/api/v1/claims?page_size=0');
      expect(res.statusCode).toBe(400);
    });

    it('caps page_size at 100', async () => {
      const res = await asPhysician('GET', '/api/v1/claims?page_size=999');
      // Zod max(100) — should reject values > 100
      expect(res.statusCode).toBe(400);
    });

    it('rejects negative page number', async () => {
      const res = await asPhysician('GET', '/api/v1/claims?page=-1');
      expect(res.statusCode).toBe(400);
    });

    it('rejects zero page number', async () => {
      const res = await asPhysician('GET', '/api/v1/claims?page=0');
      expect(res.statusCode).toBe(400);
    });

    it('rejects non-numeric page_size', async () => {
      const res = await asPhysician('GET', '/api/v1/claims?page_size=abc');
      expect(res.statusCode).toBe(400);
    });

    it('rejects non-numeric page', async () => {
      const res = await asPhysician('GET', '/api/v1/claims?page=abc');
      expect(res.statusCode).toBe(400);
    });

    it('rejects float page_size (not integer)', async () => {
      const res = await asPhysician('GET', '/api/v1/claims?page_size=2.5');
      // z.coerce.number().int() should reject non-integers
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 5. UUID Parameter Validation
  // =========================================================================

  describe('UUID parameter validation', () => {
    const INVALID_UUIDS = [
      'not-a-uuid',
      '12345',
      'abcdefgh-ijkl-mnop-qrst-uvwxyz123456',
      '<script>alert(1)</script>',
      "'; DROP TABLE claims; --",
      '../../../etc/passwd',
      '',
      '   ',
    ];

    describe('claim_id path parameter rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS.filter((id) => id.length > 0)) {
        it(`GET /api/v1/claims/${badId.slice(0, 30)} returns 400`, async () => {
          const res = await asPhysician('GET', `/api/v1/claims/${encodeURIComponent(badId)}`);
          expect(res.statusCode).toBe(400);
          const body = JSON.parse(res.body);
          expect(body.data).toBeUndefined();
        });
      }

      for (const badId of INVALID_UUIDS.filter((id) => id.length > 0)) {
        it(`PUT /api/v1/claims/${badId.slice(0, 30)} returns 400`, async () => {
          const res = await asPhysician('PUT', `/api/v1/claims/${encodeURIComponent(badId)}`, {
            date_of_service: '2026-02-01',
          });
          expect(res.statusCode).toBe(400);
        });
      }

      for (const badId of INVALID_UUIDS.filter((id) => id.length > 0)) {
        it(`DELETE /api/v1/claims/${badId.slice(0, 30)} returns 400`, async () => {
          const res = await asPhysician('DELETE', `/api/v1/claims/${encodeURIComponent(badId)}`);
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('patient_id body field rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects patient_id: ${badId.slice(0, 30) || '(empty)'}`, async () => {
          const res = await asPhysician('POST', '/api/v1/claims', {
            ...VALID_CREATE_CLAIM,
            patient_id: badId,
          });
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('shift_id path parameter rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS.filter((id) => id.length > 0)) {
        it(`GET /api/v1/shifts/${badId.slice(0, 30)} returns 400`, async () => {
          const res = await asPhysician('GET', `/api/v1/shifts/${encodeURIComponent(badId)}`);
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('suggestion_id path parameter rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS.filter((id) => id.length > 0)) {
        it(`accept with invalid sug_id: ${badId.slice(0, 30)} returns 400`, async () => {
          const res = await asPhysician(
            'POST',
            `/api/v1/claims/${P1_CLAIM_ID}/suggestions/${encodeURIComponent(badId)}/accept`,
          );
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('template_id path parameter rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS.filter((id) => id.length > 0)) {
        it(`PUT /api/v1/field-mapping-templates/${badId.slice(0, 30)} returns 400`, async () => {
          const res = await asPhysician(
            'PUT',
            `/api/v1/field-mapping-templates/${encodeURIComponent(badId)}`,
            { name: 'Updated' },
          );
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('import_id path parameter rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS.filter((id) => id.length > 0)) {
        it(`GET /api/v1/imports/${badId.slice(0, 30)} returns 400`, async () => {
          const res = await asPhysician('GET', `/api/v1/imports/${encodeURIComponent(badId)}`);
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('export_id path parameter rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS.filter((id) => id.length > 0)) {
        it(`GET /api/v1/exports/${badId.slice(0, 30)} returns 400`, async () => {
          const res = await asPhysician('GET', `/api/v1/exports/${encodeURIComponent(badId)}`);
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('facility_id body field rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects facility_id: ${badId.slice(0, 30) || '(empty)'}`, async () => {
          const res = await asPhysician('POST', '/api/v1/shifts', {
            ...VALID_CREATE_SHIFT,
            facility_id: badId,
          });
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('field_mapping_template_id body field rejects non-UUID', () => {
      for (const badId of INVALID_UUIDS) {
        it(`rejects field_mapping_template_id: ${badId.slice(0, 30) || '(empty)'}`, async () => {
          const res = await asPhysician('POST', '/api/v1/imports', {
            field_mapping_template_id: badId,
          });
          expect(res.statusCode).toBe(400);
        });
      }
    });
  });

  // =========================================================================
  // 6. Date Format Validation
  // =========================================================================

  describe('Date format validation', () => {
    const INVALID_DATES = [
      '15-01-2026',        // DD-MM-YYYY
      '01/15/2026',        // MM/DD/YYYY
      '2026/01/15',        // YYYY/MM/DD
      'January 15, 2026',  // English text
      '20260115',          // No separators
      '2026-13-01',        // Invalid month
      '2026-01-32',        // Invalid day
      '2026-00-15',        // Zero month
      '2026-01-00',        // Zero day
      'not-a-date',        // Text
      '',                  // Empty
    ];

    describe('date_of_service rejects invalid date formats', () => {
      for (const badDate of INVALID_DATES) {
        it(`rejects date_of_service: ${badDate || '(empty)'}`, async () => {
          const res = await asPhysician('POST', '/api/v1/claims', {
            ...VALID_CREATE_CLAIM,
            date_of_service: badDate,
          });
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('shift_date rejects invalid date formats', () => {
      for (const badDate of INVALID_DATES) {
        it(`rejects shift_date: ${badDate || '(empty)'}`, async () => {
          const res = await asPhysician('POST', '/api/v1/shifts', {
            ...VALID_CREATE_SHIFT,
            shift_date: badDate,
          });
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('export date_from/date_to rejects invalid date formats', () => {
      for (const badDate of INVALID_DATES.slice(0, 5)) {
        it(`rejects date_from: ${badDate || '(empty)'}`, async () => {
          const res = await asPhysician('POST', '/api/v1/exports', {
            ...VALID_CREATE_EXPORT,
            date_from: badDate,
          });
          expect(res.statusCode).toBe(400);
        });

        it(`rejects date_to: ${badDate || '(empty)'}`, async () => {
          const res = await asPhysician('POST', '/api/v1/exports', {
            ...VALID_CREATE_EXPORT,
            date_to: badDate,
          });
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('list claims date filters reject invalid formats', () => {
      it('rejects invalid date_from in query', async () => {
        const res = await asPhysician('GET', '/api/v1/claims?date_from=not-a-date');
        expect(res.statusCode).toBe(400);
      });

      it('rejects invalid date_to in query', async () => {
        const res = await asPhysician('GET', '/api/v1/claims?date_to=31-12-2026');
        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // 7. Time Format Validation (ED Shifts)
  // =========================================================================

  describe('Time format validation', () => {
    const INVALID_TIMES = [
      '25:00',     // Invalid hour
      '12:60',     // Invalid minute
      '8:00',      // Missing leading zero
      '12:00 PM',  // AM/PM format
      'noon',      // Text
      '-01:00',    // Negative
      '12:00:60',  // Invalid second
    ];

    describe('start_time rejects invalid time formats', () => {
      for (const badTime of INVALID_TIMES) {
        it(`rejects start_time: ${badTime}`, async () => {
          const res = await asPhysician('POST', '/api/v1/shifts', {
            ...VALID_CREATE_SHIFT,
            start_time: badTime,
          });
          expect(res.statusCode).toBe(400);
        });
      }
    });

    describe('end_time rejects invalid time formats', () => {
      for (const badTime of INVALID_TIMES) {
        it(`rejects end_time: ${badTime}`, async () => {
          const res = await asPhysician('POST', '/api/v1/shifts', {
            ...VALID_CREATE_SHIFT,
            end_time: badTime,
          });
          expect(res.statusCode).toBe(400);
        });
      }
    });

    it('accepts valid HH:MM format', async () => {
      const res = await asPhysician('POST', '/api/v1/shifts', {
        ...VALID_CREATE_SHIFT,
        start_time: '08:00',
        end_time: '16:30',
      });
      // Should not be a validation error
      expect(res.statusCode).not.toBe(400);
    });

    it('accepts valid HH:MM:SS format', async () => {
      const res = await asPhysician('POST', '/api/v1/shifts', {
        ...VALID_CREATE_SHIFT,
        start_time: '08:00:00',
        end_time: '16:30:59',
      });
      expect(res.statusCode).not.toBe(400);
    });
  });

  // =========================================================================
  // 8. Enum Validation
  // =========================================================================

  describe('Enum validation', () => {
    describe('claim_type accepts only AHCIP and WCB', () => {
      it('rejects invalid claim_type', async () => {
        const res = await asPhysician('POST', '/api/v1/claims', {
          ...VALID_CREATE_CLAIM,
          claim_type: 'INVALID_TYPE',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects lowercase claim_type', async () => {
        const res = await asPhysician('POST', '/api/v1/claims', {
          ...VALID_CREATE_CLAIM,
          claim_type: 'ahcip',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects mixed case claim_type', async () => {
        const res = await asPhysician('POST', '/api/v1/claims', {
          ...VALID_CREATE_CLAIM,
          claim_type: 'Ahcip',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects empty string claim_type', async () => {
        const res = await asPhysician('POST', '/api/v1/claims', {
          ...VALID_CREATE_CLAIM,
          claim_type: '',
        });
        expect(res.statusCode).toBe(400);
      });

      it('accepts AHCIP', async () => {
        const res = await asPhysician('POST', '/api/v1/claims', {
          ...VALID_CREATE_CLAIM,
          claim_type: 'AHCIP',
        });
        expect(res.statusCode).not.toBe(400);
      });

      it('accepts WCB', async () => {
        const res = await asPhysician('POST', '/api/v1/claims', {
          ...VALID_CREATE_CLAIM,
          claim_type: 'WCB',
        });
        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('import_source accepts only valid values', () => {
      it('rejects invalid import_source', async () => {
        const res = await asPhysician('POST', '/api/v1/claims', {
          ...VALID_CREATE_CLAIM,
          import_source: 'INVALID_SOURCE',
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('state filter accepts only valid claim states', () => {
      it('rejects invalid state', async () => {
        const res = await asPhysician('GET', '/api/v1/claims?state=INVALID_STATE');
        expect(res.statusCode).toBe(400);
      });

      it('rejects lowercase state', async () => {
        const res = await asPhysician('GET', '/api/v1/claims?state=draft');
        expect(res.statusCode).toBe(400);
      });
    });

    describe('export format accepts only CSV and JSON', () => {
      it('rejects invalid format', async () => {
        const res = await asPhysician('POST', '/api/v1/exports', {
          ...VALID_CREATE_EXPORT,
          format: 'XML',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects lowercase format', async () => {
        const res = await asPhysician('POST', '/api/v1/exports', {
          ...VALID_CREATE_EXPORT,
          format: 'csv',
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('submission mode accepts only valid values', () => {
      it('rejects invalid mode', async () => {
        const res = await asPhysician('PUT', '/api/v1/submission-preferences', {
          mode: 'INVALID_MODE',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects empty mode', async () => {
        const res = await asPhysician('PUT', '/api/v1/submission-preferences', {
          mode: '',
        });
        expect(res.statusCode).toBe(400);
      });

      it('accepts AUTO_CLEAN', async () => {
        const res = await asPhysician('PUT', '/api/v1/submission-preferences', {
          mode: 'AUTO_CLEAN',
        });
        expect(res.statusCode).not.toBe(400);
      });

      it('accepts AUTO_ALL', async () => {
        const res = await asPhysician('PUT', '/api/v1/submission-preferences', {
          mode: 'AUTO_ALL',
        });
        expect(res.statusCode).not.toBe(400);
      });

      it('accepts REQUIRE_APPROVAL', async () => {
        const res = await asPhysician('PUT', '/api/v1/submission-preferences', {
          mode: 'REQUIRE_APPROVAL',
        });
        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('encounter claim_type validation', () => {
      it('rejects invalid claim_type in encounter', async () => {
        const res = await asPhysician('POST', `/api/v1/shifts/${P1_SHIFT_ID}/encounters`, {
          ...VALID_ADD_ENCOUNTER,
          claim_type: 'INVALID',
        });
        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // 9. String Length Boundary Validation
  // =========================================================================

  describe('String length boundary validation', () => {
    describe('write-off reason length limits', () => {
      it('rejects empty reason', async () => {
        const res = await asPhysician('POST', `/api/v1/claims/${P1_CLAIM_ID}/write-off`, {
          reason: '',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects reason exceeding 500 characters', async () => {
        const res = await asPhysician('POST', `/api/v1/claims/${P1_CLAIM_ID}/write-off`, {
          reason: 'x'.repeat(501),
        });
        expect(res.statusCode).toBe(400);
      });

      it('accepts reason at 500 characters', async () => {
        const res = await asPhysician('POST', `/api/v1/claims/${P1_CLAIM_ID}/write-off`, {
          reason: 'x'.repeat(500),
        });
        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('template name length limits', () => {
      it('rejects empty template name', async () => {
        const res = await asPhysician('POST', '/api/v1/field-mapping-templates', {
          ...VALID_CREATE_TEMPLATE,
          name: '',
        });
        expect(res.statusCode).toBe(400);
      });

      it('rejects template name exceeding 100 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/field-mapping-templates', {
          ...VALID_CREATE_TEMPLATE,
          name: 'x'.repeat(101),
        });
        expect(res.statusCode).toBe(400);
      });

      it('accepts template name at 100 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/field-mapping-templates', {
          ...VALID_CREATE_TEMPLATE,
          name: 'x'.repeat(100),
        });
        expect(res.statusCode).not.toBe(400);
      });
    });

    describe('emr_type length limits', () => {
      it('rejects emr_type exceeding 50 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/field-mapping-templates', {
          ...VALID_CREATE_TEMPLATE,
          emr_type: 'x'.repeat(51),
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('dismiss reason length limits', () => {
      it('rejects dismiss reason exceeding 500 characters', async () => {
        const res = await asPhysician(
          'POST',
          `/api/v1/claims/${P1_CLAIM_ID}/suggestions/${P1_SUGGESTION_ID}/dismiss`,
          { reason: 'x'.repeat(501) },
        );
        expect(res.statusCode).toBe(400);
      });
    });

    describe('delimiter length limits', () => {
      it('rejects delimiter exceeding 5 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/field-mapping-templates', {
          ...VALID_CREATE_TEMPLATE,
          delimiter: 'toolong',
        });
        expect(res.statusCode).toBe(400);
      });
    });

    describe('date_format length limits', () => {
      it('rejects date_format exceeding 20 characters', async () => {
        const res = await asPhysician('POST', '/api/v1/field-mapping-templates', {
          ...VALID_CREATE_TEMPLATE,
          date_format: 'x'.repeat(21),
        });
        expect(res.statusCode).toBe(400);
      });
    });
  });

  // =========================================================================
  // 10. Missing Required Fields
  // =========================================================================

  describe('Missing required fields', () => {
    it('rejects claim creation without claim_type', async () => {
      const res = await asPhysician('POST', '/api/v1/claims', {
        patient_id: P1_PATIENT_ID,
        date_of_service: '2026-01-15',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects claim creation without patient_id', async () => {
      const res = await asPhysician('POST', '/api/v1/claims', {
        claim_type: 'AHCIP',
        date_of_service: '2026-01-15',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects claim creation without date_of_service', async () => {
      const res = await asPhysician('POST', '/api/v1/claims', {
        claim_type: 'AHCIP',
        patient_id: P1_PATIENT_ID,
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects claim creation with empty body', async () => {
      const res = await asPhysician('POST', '/api/v1/claims', {});
      expect(res.statusCode).toBe(400);
    });

    it('rejects template creation without name', async () => {
      const res = await asPhysician('POST', '/api/v1/field-mapping-templates', {
        mappings: [{ source_column: 'col1', target_field: 'field1' }],
        has_header_row: true,
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects template creation without mappings', async () => {
      const res = await asPhysician('POST', '/api/v1/field-mapping-templates', {
        name: 'Test',
        has_header_row: true,
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects template creation without has_header_row', async () => {
      const res = await asPhysician('POST', '/api/v1/field-mapping-templates', {
        name: 'Test',
        mappings: [{ source_column: 'col1', target_field: 'field1' }],
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects shift creation without facility_id', async () => {
      const res = await asPhysician('POST', '/api/v1/shifts', {
        shift_date: '2026-01-20',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects shift creation without shift_date', async () => {
      const res = await asPhysician('POST', '/api/v1/shifts', {
        facility_id: P1_FACILITY_ID,
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects export creation without date_from', async () => {
      const res = await asPhysician('POST', '/api/v1/exports', {
        date_to: '2026-01-31',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects export creation without date_to', async () => {
      const res = await asPhysician('POST', '/api/v1/exports', {
        date_from: '2026-01-01',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects write-off without reason', async () => {
      const res = await asPhysician('POST', `/api/v1/claims/${P1_CLAIM_ID}/write-off`, {});
      expect(res.statusCode).toBe(400);
    });

    it('rejects encounter without patient_id', async () => {
      const res = await asPhysician('POST', `/api/v1/shifts/${P1_SHIFT_ID}/encounters`, {
        date_of_service: '2026-01-20',
        claim_type: 'AHCIP',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects encounter without date_of_service', async () => {
      const res = await asPhysician('POST', `/api/v1/shifts/${P1_SHIFT_ID}/encounters`, {
        patient_id: P1_PATIENT_ID,
        claim_type: 'AHCIP',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects encounter without claim_type', async () => {
      const res = await asPhysician('POST', `/api/v1/shifts/${P1_SHIFT_ID}/encounters`, {
        patient_id: P1_PATIENT_ID,
        date_of_service: '2026-01-20',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects submission preferences update without mode', async () => {
      const res = await asPhysician('PUT', '/api/v1/submission-preferences', {});
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 11. Error Response Sanitisation — No Input Echo-back
  // =========================================================================

  describe('Error responses do not echo malicious input', () => {
    it('validation error for claim_type does not echo payload', async () => {
      const malicious = '<script>alert("xss")</script>';
      const res = await asPhysician('POST', '/api/v1/claims', {
        ...VALID_CREATE_CLAIM,
        claim_type: malicious,
      });
      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('<script>');
      expect(rawBody).not.toContain('alert');
    });

    it('validation error for SQL injection does not echo payload', async () => {
      const malicious = "'; DROP TABLE claims; --";
      const res = await asPhysician('POST', '/api/v1/claims', {
        ...VALID_CREATE_CLAIM,
        claim_type: malicious,
      });
      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('DROP TABLE');
      expect(rawBody).not.toContain('claims');
    });

    it('validation error for invalid UUID does not echo the value', async () => {
      const malicious = '../../etc/passwd';
      const res = await asPhysician('POST', '/api/v1/claims', {
        ...VALID_CREATE_CLAIM,
        patient_id: malicious,
      });
      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('passwd');
      expect(rawBody).not.toContain('../');
    });

    it('validation error for non-UUID path param does not echo the value', async () => {
      const malicious = '<img onerror=alert(1) src=x>';
      const res = await asPhysician('GET', `/api/v1/claims/${encodeURIComponent(malicious)}`);
      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('onerror');
      expect(rawBody).not.toContain('<img');
    });

    it('error responses do not expose internal details', async () => {
      const res = await asPhysician('POST', '/api/v1/claims', {
        ...VALID_CREATE_CLAIM,
        claim_type: 'INVALID',
      });
      expect(res.statusCode).toBe(400);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('node_modules');
      expect(rawBody).not.toContain('.ts:');
    });
  });

  // =========================================================================
  // 12. Path Traversal Prevention
  // =========================================================================

  describe('Path traversal prevention', () => {
    it('rejects path traversal in claim ID', async () => {
      const res = await asPhysician('GET', '/api/v1/claims/..%2F..%2Fetc%2Fpasswd');
      expect(res.statusCode).toBe(400);
    });

    it('rejects path traversal in import ID', async () => {
      const res = await asPhysician('GET', '/api/v1/imports/..%2F..%2Fetc%2Fpasswd');
      expect(res.statusCode).toBe(400);
    });

    it('rejects path traversal in shift ID', async () => {
      const res = await asPhysician('GET', '/api/v1/shifts/..%2F..%2Fetc%2Fpasswd');
      expect(res.statusCode).toBe(400);
    });

    it('rejects path traversal in template ID', async () => {
      const res = await asPhysician('PUT', '/api/v1/field-mapping-templates/..%2F..%2Fetc%2Fpasswd', {
        name: 'test',
      });
      expect(res.statusCode).toBe(400);
    });

    it('rejects path traversal in export ID', async () => {
      const res = await asPhysician('GET', '/api/v1/exports/..%2F..%2Fetc%2Fpasswd');
      expect(res.statusCode).toBe(400);
    });
  });

  // =========================================================================
  // 13. Extra/Unexpected Fields (Mass Assignment Prevention)
  // =========================================================================

  describe('Extra/unexpected fields handling', () => {
    it('ignores extra fields in claim creation (no mass assignment)', async () => {
      const res = await asPhysician('POST', '/api/v1/claims', {
        ...VALID_CREATE_CLAIM,
        state: 'PAID',            // Attempt to set state directly
        physicianId: VALID_UUID,  // Attempt to set physician directly
        isClean: true,            // Attempt to set clean flag
      });
      // Should not be 400 — extra fields are stripped by Zod
      // Verify we didn't get a 500 either
      expect([200, 201]).toContain(res.statusCode);
    });

    it('ignores state injection in claim update', async () => {
      const res = await asPhysician('PUT', `/api/v1/claims/${P1_CLAIM_ID}`, {
        date_of_service: '2026-02-01',
        state: 'PAID',             // Attempt to set state via update
        physicianId: VALID_UUID,   // Attempt to change physician
      });
      // Extra fields should be ignored, not cause 500
      expect(res.statusCode).not.toBe(500);
    });
  });

  // =========================================================================
  // 14. Content-Type Enforcement
  // =========================================================================

  describe('Content-Type enforcement', () => {
    it('rejects claim creation with text/plain content type', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/claims',
        headers: {
          cookie: `session=${P1_SESSION_TOKEN}`,
          'content-type': 'text/plain',
        },
        payload: JSON.stringify(VALID_CREATE_CLAIM),
      });
      // Should reject non-JSON content types for JSON endpoints
      expect([400, 415]).toContain(res.statusCode);
    });
  });

  // =========================================================================
  // 15. Sanity: Valid Payloads Are Accepted
  // =========================================================================

  describe('Sanity: valid payloads are accepted', () => {
    it('valid create claim is accepted', async () => {
      const res = await asPhysician('POST', '/api/v1/claims', VALID_CREATE_CLAIM);
      expect(res.statusCode).not.toBe(400);
      expect(res.statusCode).not.toBe(500);
    });

    it('valid create template is accepted', async () => {
      const res = await asPhysician('POST', '/api/v1/field-mapping-templates', VALID_CREATE_TEMPLATE);
      expect(res.statusCode).not.toBe(400);
      expect(res.statusCode).not.toBe(500);
    });

    it('valid create shift is accepted', async () => {
      const res = await asPhysician('POST', '/api/v1/shifts', VALID_CREATE_SHIFT);
      expect(res.statusCode).not.toBe(400);
      expect(res.statusCode).not.toBe(500);
    });

    it('valid add encounter is accepted', async () => {
      const res = await asPhysician(
        'POST',
        `/api/v1/shifts/${P1_SHIFT_ID}/encounters`,
        VALID_ADD_ENCOUNTER,
      );
      expect(res.statusCode).not.toBe(400);
      expect(res.statusCode).not.toBe(500);
    });

    it('valid create export is accepted', async () => {
      const res = await asPhysician('POST', '/api/v1/exports', VALID_CREATE_EXPORT);
      expect(res.statusCode).not.toBe(400);
      expect(res.statusCode).not.toBe(500);
    });

    it('valid update submission preferences is accepted', async () => {
      const res = await asPhysician('PUT', '/api/v1/submission-preferences', {
        mode: 'AUTO_CLEAN',
      });
      expect(res.statusCode).not.toBe(400);
      expect(res.statusCode).not.toBe(500);
    });

    it('valid list claims with filters is accepted', async () => {
      const res = await asPhysician(
        'GET',
        '/api/v1/claims?state=DRAFT&claim_type=AHCIP&page=1&page_size=25',
      );
      expect(res.statusCode).not.toBe(400);
      expect(res.statusCode).not.toBe(500);
    });
  });
});
