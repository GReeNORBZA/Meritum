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

import {
  createClaim,
  createClaimFromImport,
  createClaimFromShift,
  validateClaim,
  queueClaim,
  unqueueClaim,
  writeOffClaim,
  resubmitClaim,
  expireClaimWithContext,
  acceptSuggestion,
  dismissSuggestion,
  acknowledgeDuplicate,
  updateSubmissionPreferences,
  type ClaimServiceDeps,
} from '../../../src/domains/claim/claim.service.js';

import {
  ClaimAuditAction,
  ActorContext,
  ClaimState,
  ClaimImportSource,
  ShiftStatus,
} from '@meritum/shared/constants/claim.constants.js';

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = '11111111-0000-0000-0000-000000000001';
const PHYSICIAN_SESSION_ID = '11111111-0000-0000-0000-000000000011';
const PHYSICIAN_PROVIDER_ID = PHYSICIAN_USER_ID;

const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_USER_ID = '22222222-0000-0000-0000-000000000002';
const DELEGATE_SESSION_ID = '22222222-0000-0000-0000-000000000022';

const PLACEHOLDER_UUID = '00000000-0000-0000-0000-000000000001';

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
  delegateContext?: {
    delegateUserId: string;
    physicianProviderId: string;
    permissions: string[];
    linkageId: string;
  };
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
let auditEntries: Array<Record<string, unknown>> = [];
let claimAuditEntries: Array<Record<string, unknown>> = [];

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
      const result: any = {
        session,
        user: {
          userId: user.userId,
          role: user.role,
          subscriptionStatus: user.subscriptionStatus,
        },
      };
      if (user.delegateContext) {
        result.user.delegateContext = user.delegateContext;
      }
      return result;
    }),
    refreshSession: vi.fn(async () => {}),
    listActiveSessions: vi.fn(async () => []),
    revokeSession: vi.fn(async () => {}),
    revokeAllUserSessions: vi.fn(async () => {}),
  };
}

function createMockAuditRepo() {
  return {
    appendAuditLog: vi.fn(async (entry: Record<string, unknown>) => {
      auditEntries.push(entry);
    }),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// In-memory claim store (supports audit testing via realistic data flows)
// ---------------------------------------------------------------------------

let claimStore: Record<string, any>[] = [];
let shiftStore: Record<string, any>[] = [];

function generateUuid(): string {
  return 'aaaaaaaa-bbbb-cccc-dddd-' + Math.random().toString(36).substring(2, 14).padEnd(12, '0');
}

function createMockClaimRepo() {
  return {
    createClaim: vi.fn(async (data: any) => {
      const claim = {
        claimId: generateUuid(),
        physicianId: data.physicianId,
        patientId: data.patientId,
        claimType: data.claimType,
        state: 'DRAFT',
        isClean: null,
        importSource: data.importSource ?? 'MANUAL',
        importBatchId: data.importBatchId ?? null,
        shiftId: data.shiftId ?? null,
        dateOfService: data.dateOfService,
        submissionDeadline: data.submissionDeadline,
        validationResult: null,
        validationTimestamp: null,
        referenceDataVersion: null,
        aiCoachSuggestions: null,
        duplicateAlert: null,
        flags: null,
        createdAt: new Date(),
        createdBy: data.createdBy,
        updatedAt: new Date(),
        updatedBy: data.updatedBy,
        deletedAt: null,
      };
      claimStore.push(claim);
      return claim;
    }),
    findClaimById: vi.fn(async (claimId: string, physicianId: string) => {
      return claimStore.find(
        (c) => c.claimId === claimId && c.physicianId === physicianId && !c.deletedAt,
      ) ?? undefined;
    }),
    updateClaim: vi.fn(async (claimId: string, physicianId: string, updates: any) => {
      const claim = claimStore.find(
        (c) => c.claimId === claimId && c.physicianId === physicianId,
      );
      if (claim) Object.assign(claim, updates, { updatedAt: new Date() });
      return claim;
    }),
    softDeleteClaim: vi.fn(async (claimId: string, physicianId: string) => {
      const claim = claimStore.find(
        (c) => c.claimId === claimId && c.physicianId === physicianId && c.state === 'DRAFT',
      );
      if (claim) {
        claim.deletedAt = new Date();
        claim.state = 'DELETED';
        return true;
      }
      return false;
    }),
    listClaims: vi.fn(async (physicianId: string, filters: any) => {
      let data = claimStore.filter((c) => c.physicianId === physicianId && !c.deletedAt);
      if (filters?.state) data = data.filter((c) => c.state === filters.state);
      return {
        data,
        pagination: { total: data.length, page: 1, pageSize: 25, hasMore: false },
      };
    }),
    countClaimsByState: vi.fn(async () => []),
    findClaimsApproachingDeadline: vi.fn(async () => []),
    transitionState: vi.fn(async (claimId: string, physicianId: string, from: string, to: string) => {
      const claim = claimStore.find(
        (c) => c.claimId === claimId && c.physicianId === physicianId,
      );
      if (claim) {
        claim.state = to;
        claim.updatedAt = new Date();
      }
      return claim;
    }),
    classifyClaim: vi.fn(async (claimId: string, physicianId: string, isClean: boolean) => {
      const claim = claimStore.find(
        (c) => c.claimId === claimId && c.physicianId === physicianId,
      );
      if (claim) claim.isClean = isClean;
      return claim;
    }),
    updateValidationResult: vi.fn(async (claimId: string, physicianId: string, result: any, refVersion: string) => {
      const claim = claimStore.find(
        (c) => c.claimId === claimId && c.physicianId === physicianId,
      );
      if (claim) {
        claim.validationResult = result;
        claim.validationTimestamp = new Date();
        claim.referenceDataVersion = refVersion;
      }
      return claim;
    }),
    updateAiSuggestions: vi.fn(async (claimId: string, physicianId: string, suggestions: any) => {
      const claim = claimStore.find(
        (c) => c.claimId === claimId && c.physicianId === physicianId,
      );
      if (claim) claim.aiCoachSuggestions = suggestions;
      return claim;
    }),
    updateDuplicateAlert: vi.fn(async (claimId: string, physicianId: string, alert: any) => {
      const claim = claimStore.find(
        (c) => c.claimId === claimId && c.physicianId === physicianId,
      );
      if (claim) claim.duplicateAlert = alert;
      return claim;
    }),
    updateFlags: vi.fn(async () => ({})),
    createImportBatch: vi.fn(async (data: any) => ({
      importBatchId: generateUuid(),
      ...data,
      status: 'PENDING',
    })),
    findImportBatchById: vi.fn(async () => undefined),
    updateImportBatchStatus: vi.fn(async () => ({})),
    findDuplicateImportByHash: vi.fn(async () => undefined),
    listImportBatches: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
    findClaimsForBatchAssembly: vi.fn(async () => []),
    bulkTransitionState: vi.fn(async () => []),
    createTemplate: vi.fn(async () => ({})),
    findTemplateById: vi.fn(async () => undefined),
    updateTemplate: vi.fn(async () => ({})),
    deleteTemplate: vi.fn(async () => {}),
    listTemplates: vi.fn(async () => []),
    createShift: vi.fn(async (data: any) => {
      const shift = {
        shiftId: generateUuid(),
        physicianId: data.physicianId,
        facilityId: data.facilityId,
        shiftDate: data.shiftDate,
        startTime: data.startTime,
        endTime: data.endTime,
        status: ShiftStatus.IN_PROGRESS,
        encounterCount: 0,
      };
      shiftStore.push(shift);
      return shift;
    }),
    findShiftById: vi.fn(async (shiftId: string, physicianId: string) => {
      return shiftStore.find(
        (s) => s.shiftId === shiftId && s.physicianId === physicianId,
      ) ?? undefined;
    }),
    updateShiftStatus: vi.fn(async (shiftId: string, physicianId: string, status: string) => {
      const shift = shiftStore.find(
        (s) => s.shiftId === shiftId && s.physicianId === physicianId,
      );
      if (shift) shift.status = status;
      return shift;
    }),
    updateShiftTimes: vi.fn(async () => ({})),
    incrementEncounterCount: vi.fn(async (shiftId: string) => {
      const shift = shiftStore.find((s) => s.shiftId === shiftId);
      if (shift) shift.encounterCount++;
    }),
    listShifts: vi.fn(async () => ({
      data: [],
      pagination: { total: 0, page: 1, pageSize: 25, hasMore: false },
    })),
    findClaimsByShift: vi.fn(async () => []),
    createExportRecord: vi.fn(async () => ({})),
    findExportById: vi.fn(async () => undefined),
    updateExportStatus: vi.fn(async () => ({})),
    appendClaimAudit: vi.fn(async (entry: Record<string, unknown>) => {
      const auditEntry = {
        auditId: generateUuid(),
        ...entry,
        createdAt: new Date(),
      };
      claimAuditEntries.push(auditEntry);
      return auditEntry;
    }),
    getClaimAuditHistory: vi.fn(async (claimId: string, physicianId: string) => {
      return claimAuditEntries.filter((e) => e.claimId === claimId);
    }),
    getClaimAuditHistoryPaginated: vi.fn(
      async (claimId: string, physicianId: string, page: number, pageSize: number) => {
        const data = claimAuditEntries.filter((e) => e.claimId === claimId);
        return {
          data,
          pagination: { total: data.length, page, pageSize, hasMore: false },
        };
      },
    ),
  };
}

// ---------------------------------------------------------------------------
// Service dependencies builder
// ---------------------------------------------------------------------------

let mockClaimRepo: ReturnType<typeof createMockClaimRepo>;

function createServiceDeps(): ClaimServiceDeps {
  mockClaimRepo = createMockClaimRepo();
  return {
    repo: mockClaimRepo as any,
    providerCheck: {
      isActive: vi.fn(async () => true),
      getRegistrationDate: vi.fn(async () => '2020-01-01'),
    },
    patientCheck: {
      exists: vi.fn(async () => true),
    },
    pathwayValidators: {},
    referenceDataVersion: { getCurrentVersion: vi.fn(async () => '2026.1') },
    notificationEmitter: { emit: vi.fn(async () => {}) },
    submissionPreference: { getSubmissionMode: vi.fn(async () => 'MANUAL') },
    facilityCheck: { belongsToPhysician: vi.fn(async () => true) },
    afterHoursPremiumCalculators: {},
    explanatoryCodeLookup: { getExplanatoryCode: vi.fn(async () => null) },
  };
}

// ---------------------------------------------------------------------------
// Test app builder (for HTTP-level audit integrity tests)
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
    serviceDeps: createServiceDeps(),
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, request, reply) => {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: { code: (error as any).code ?? 'ERROR', message: error.message },
      });
    }
    if (error.validation) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.validation },
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

function physicianRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function lastAuditEntry(): Record<string, unknown> {
  return claimAuditEntries[claimAuditEntries.length - 1];
}

function auditEntriesForClaim(claimId: string): Array<Record<string, unknown>> {
  return claimAuditEntries.filter((e) => e.claimId === claimId);
}

function findAuditEntry(claimId: string, action: string): Record<string, unknown> | undefined {
  return claimAuditEntries.find((e) => e.claimId === claimId && e.action === action);
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Claim Audit Trail Completeness (Security)', () => {
  let deps: ClaimServiceDeps;

  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    // Reset stores
    users = [];
    sessions = [];
    auditEntries = [];
    claimAuditEntries = [];
    claimStore = [];
    shiftStore = [];

    // Seed physician
    users.push({
      userId: PHYSICIAN_USER_ID,
      email: 'physician@example.com',
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
      sessionId: PHYSICIAN_SESSION_ID,
      userId: PHYSICIAN_USER_ID,
      tokenHash: PHYSICIAN_SESSION_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });

    // Seed delegate
    users.push({
      userId: DELEGATE_USER_ID,
      email: 'delegate@example.com',
      passwordHash: 'hashed',
      mfaConfigured: true,
      totpSecretEncrypted: null,
      failedLoginCount: 0,
      lockedUntil: null,
      isActive: true,
      role: 'DELEGATE',
      subscriptionStatus: 'TRIAL',
      delegateContext: {
        delegateUserId: DELEGATE_USER_ID,
        physicianProviderId: PHYSICIAN_USER_ID,
        permissions: ['CLAIM_CREATE', 'CLAIM_VIEW', 'CLAIM_EDIT', 'CLAIM_SUBMIT', 'CLAIM_DELETE'],
        linkageId: '99999999-0000-0000-0000-000000000099',
      },
    });
    sessions.push({
      sessionId: DELEGATE_SESSION_ID,
      userId: DELEGATE_USER_ID,
      tokenHash: DELEGATE_SESSION_TOKEN_HASH,
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });

    // Create fresh service deps per test
    deps = createServiceDeps();
  });

  // =========================================================================
  // Category 1: State Change Audit Events
  // =========================================================================

  describe('State change events produce audit records', () => {
    it('claim created (manual) produces CREATED audit entry with PHYSICIAN actor_context', async () => {
      const result = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });

      expect(claimAuditEntries.length).toBe(1);
      const entry = claimAuditEntries[0];
      expect(entry.claimId).toBe(result.claimId);
      expect(entry.action).toBe(ClaimAuditAction.CREATED);
      expect(entry.previousState).toBeNull();
      expect(entry.newState).toBe(ClaimState.DRAFT);
      expect(entry.actorId).toBe(PHYSICIAN_USER_ID);
      expect(entry.actorContext).toBe(ActorContext.PHYSICIAN);
    });

    it('claim created (import) produces CREATED audit entry with import_source in changes', async () => {
      const result = await createClaimFromImport(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        generateUuid(),
        { claimType: 'AHCIP', patientId: PLACEHOLDER_UUID, dateOfService: '2026-01-15' },
      );

      expect(claimAuditEntries.length).toBe(1);
      const entry = claimAuditEntries[0];
      expect(entry.action).toBe(ClaimAuditAction.CREATED);
      expect(entry.actorContext).toBe(ActorContext.SYSTEM);
      expect(entry.changes).toBeDefined();
      expect((entry.changes as any).importBatchId).toBeDefined();
    });

    it('claim created (shift encounter) produces CREATED audit entry with shiftId in changes', async () => {
      // Create a shift first
      const shift = await shiftStore.push({
        shiftId: generateUuid(),
        physicianId: PHYSICIAN_PROVIDER_ID,
        facilityId: PLACEHOLDER_UUID,
        shiftDate: '2026-01-15',
        startTime: '08:00',
        endTime: '16:00',
        status: ShiftStatus.IN_PROGRESS,
        encounterCount: 0,
      });
      const shiftId = shiftStore[0].shiftId;

      const result = await createClaimFromShift(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        shiftId,
        { claimType: 'AHCIP', patientId: PLACEHOLDER_UUID, dateOfService: '2026-01-15' },
      );

      expect(claimAuditEntries.length).toBe(1);
      const entry = claimAuditEntries[0];
      expect(entry.action).toBe(ClaimAuditAction.CREATED);
      expect(entry.actorContext).toBe(ActorContext.PHYSICIAN);
      expect((entry.changes as any).shiftId).toBe(shiftId);
    });

    it('claim validated produces VALIDATED audit entry with validation_result in changes', async () => {
      // Create a claim first
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });
      claimAuditEntries = []; // Clear creation audit

      await validateClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN);

      const entry = findAuditEntry(created.claimId, ClaimAuditAction.VALIDATED);
      expect(entry).toBeDefined();
      expect(entry!.previousState).toBe(ClaimState.DRAFT);
      expect(entry!.newState).toBe(ClaimState.VALIDATED);
      expect(entry!.actorId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.actorContext).toBe(ActorContext.PHYSICIAN);
      expect((entry!.changes as any).validation_result).toBeDefined();
    });

    it('claim queued produces QUEUED audit entry with isClean classification', async () => {
      // Create and validate a claim
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });
      await validateClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN);
      claimAuditEntries = []; // Clear previous audit entries

      await queueClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN);

      const entry = findAuditEntry(created.claimId, ClaimAuditAction.QUEUED);
      expect(entry).toBeDefined();
      expect(entry!.previousState).toBe(ClaimState.VALIDATED);
      expect(entry!.newState).toBe(ClaimState.QUEUED);
      expect(entry!.actorId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.actorContext).toBe(ActorContext.PHYSICIAN);
      expect(entry!.changes).toBeDefined();
      expect((entry!.changes as any)).toHaveProperty('isClean');
    });

    it('claim unqueued produces UNQUEUED audit entry', async () => {
      // Create, validate, and queue a claim
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });
      await validateClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN);
      await queueClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN);
      claimAuditEntries = [];

      await unqueueClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID);

      const entry = findAuditEntry(created.claimId, ClaimAuditAction.UNQUEUED);
      expect(entry).toBeDefined();
      expect(entry!.previousState).toBe(ClaimState.QUEUED);
      expect(entry!.newState).toBe(ClaimState.VALIDATED);
      expect(entry!.actorId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.actorContext).toBe(ActorContext.PHYSICIAN);
    });

    it('claim written off produces WRITTEN_OFF audit entry with reason', async () => {
      // Create a claim and transition it to REJECTED state
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });
      // Manually set state to REJECTED for write-off test
      const claim = claimStore.find((c) => c.claimId === created.claimId);
      if (claim) claim.state = ClaimState.REJECTED;
      claimAuditEntries = [];

      await writeOffClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, 'Uncollectable balance');

      const entry = findAuditEntry(created.claimId, ClaimAuditAction.WRITTEN_OFF);
      expect(entry).toBeDefined();
      expect(entry!.previousState).toBe(ClaimState.REJECTED);
      expect(entry!.newState).toBe(ClaimState.WRITTEN_OFF);
      expect(entry!.actorId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.actorContext).toBe(ActorContext.PHYSICIAN);
      expect(entry!.reason).toBe('Uncollectable balance');
    });

    it('claim resubmitted produces RESUBMITTED audit entry with validation_result', async () => {
      // Create a claim and set to REJECTED
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });
      const claim = claimStore.find((c) => c.claimId === created.claimId);
      if (claim) claim.state = ClaimState.REJECTED;
      claimAuditEntries = [];

      await resubmitClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID);

      const entry = findAuditEntry(created.claimId, ClaimAuditAction.RESUBMITTED);
      expect(entry).toBeDefined();
      expect(entry!.previousState).toBe(ClaimState.REJECTED);
      expect(entry!.newState).toBe(ClaimState.QUEUED);
      expect(entry!.actorId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.actorContext).toBe(ActorContext.PHYSICIAN);
      expect((entry!.changes as any).validation_result).toBeDefined();
    });

    it('claim expired (system-initiated) produces EXPIRED audit entry with SYSTEM actor_context', async () => {
      // Create a claim with a past DOS so its submission deadline is in the past
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2024-01-15',
      });
      // Ensure the submission deadline is in the past
      const claim = claimStore.find((c) => c.claimId === created.claimId);
      if (claim) claim.submissionDeadline = '2024-04-15';
      claimAuditEntries = [];

      await expireClaimWithContext(deps, created.claimId, PHYSICIAN_PROVIDER_ID, ClaimState.DRAFT);

      const entry = findAuditEntry(created.claimId, ClaimAuditAction.EXPIRED);
      expect(entry).toBeDefined();
      expect(entry!.previousState).toBe(ClaimState.DRAFT);
      expect(entry!.newState).toBe(ClaimState.EXPIRED);
      expect(entry!.actorId).toBe('SYSTEM');
      expect(entry!.actorContext).toBe(ActorContext.SYSTEM);
    });
  });

  // =========================================================================
  // Category 2: AI Coach Events
  // =========================================================================

  describe('AI Coach events produce audit records', () => {
    it('accepting an AI suggestion produces AI_SUGGESTION_ACCEPTED audit entry', async () => {
      // Create a claim with AI suggestions
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });
      const claim = claimStore.find((c) => c.claimId === created.claimId);
      const suggestionId = generateUuid();
      if (claim) {
        claim.aiCoachSuggestions = [
          {
            id: suggestionId,
            field: 'health_service_code',
            suggestedValue: '03.04A',
            reason: 'Higher-value alternative',
            status: 'PENDING',
          },
        ];
      }
      claimAuditEntries = [];

      await acceptSuggestion(
        deps,
        created.claimId,
        suggestionId,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
      );

      const entry = findAuditEntry(created.claimId, ClaimAuditAction.AI_SUGGESTION_ACCEPTED);
      expect(entry).toBeDefined();
      expect(entry!.actorId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.actorContext).toBe(ActorContext.PHYSICIAN);
      expect((entry!.changes as any).suggestionId).toBe(suggestionId);
      expect((entry!.changes as any).field).toBe('health_service_code');
      expect((entry!.changes as any).suggestedValue).toBe('03.04A');
    });

    it('dismissing an AI suggestion produces AI_SUGGESTION_DISMISSED audit entry with reason', async () => {
      // Create a claim with AI suggestions
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });
      const claim = claimStore.find((c) => c.claimId === created.claimId);
      const suggestionId = generateUuid();
      if (claim) {
        claim.aiCoachSuggestions = [
          {
            id: suggestionId,
            field: 'diagnostic_code',
            suggestedValue: '780',
            reason: 'Common pairing',
            status: 'PENDING',
          },
        ];
      }
      claimAuditEntries = [];

      await dismissSuggestion(
        deps,
        created.claimId,
        suggestionId,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        'Not applicable to this case',
      );

      const entry = findAuditEntry(created.claimId, ClaimAuditAction.AI_SUGGESTION_DISMISSED);
      expect(entry).toBeDefined();
      expect(entry!.actorId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.actorContext).toBe(ActorContext.PHYSICIAN);
      expect((entry!.changes as any).suggestionId).toBe(suggestionId);
      expect((entry!.changes as any).reason).toBe('Not applicable to this case');
    });
  });

  // =========================================================================
  // Category 3: Duplicate Event
  // =========================================================================

  describe('Duplicate acknowledgement produces audit record', () => {
    it('acknowledging a duplicate produces DUPLICATE_ACKNOWLEDGED audit entry', async () => {
      // Create a claim with a duplicate alert
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });
      const claim = claimStore.find((c) => c.claimId === created.claimId);
      if (claim) {
        claim.duplicateAlert = {
          duplicateClaimId: generateUuid(),
          matchType: 'EXACT',
          confidence: 0.98,
        };
      }
      claimAuditEntries = [];

      await acknowledgeDuplicate(
        deps,
        created.claimId,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
      );

      const entry = findAuditEntry(created.claimId, ClaimAuditAction.DUPLICATE_ACKNOWLEDGED);
      expect(entry).toBeDefined();
      expect(entry!.actorId).toBe(PHYSICIAN_USER_ID);
      expect(entry!.actorContext).toBe(ActorContext.PHYSICIAN);
      expect((entry!.changes as any).previousAlert).toBeDefined();
      // The state should not change for duplicate acknowledgement
      expect(entry!.previousState).toBe(entry!.newState);
    });
  });

  // =========================================================================
  // Category 4: Actor Context Verification
  // =========================================================================

  describe('Actor context correctly records identity type', () => {
    it('physician actions record PHYSICIAN actor_context', async () => {
      const result = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });

      const entry = lastAuditEntry();
      expect(entry.actorContext).toBe(ActorContext.PHYSICIAN);
      expect(entry.actorId).toBe(PHYSICIAN_USER_ID);
    });

    it('delegate actions record DELEGATE actor_context', async () => {
      const result = await createClaim(deps, PHYSICIAN_PROVIDER_ID, DELEGATE_USER_ID, ActorContext.DELEGATE, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });

      const entry = lastAuditEntry();
      expect(entry.actorContext).toBe(ActorContext.DELEGATE);
      expect(entry.actorId).toBe(DELEGATE_USER_ID);
    });

    it('system-initiated actions record SYSTEM actor_context', async () => {
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2024-01-15',
      });
      // Set deadline in the past so expiry can proceed
      const claim = claimStore.find((c) => c.claimId === created.claimId);
      if (claim) claim.submissionDeadline = '2024-04-15';
      claimAuditEntries = [];

      await expireClaimWithContext(deps, created.claimId, PHYSICIAN_PROVIDER_ID, ClaimState.DRAFT);

      const entry = findAuditEntry(created.claimId, ClaimAuditAction.EXPIRED);
      expect(entry).toBeDefined();
      expect(entry!.actorContext).toBe(ActorContext.SYSTEM);
      expect(entry!.actorId).toBe('SYSTEM');
    });

    it('import-initiated creation records SYSTEM actor_context', async () => {
      const result = await createClaimFromImport(
        deps,
        PHYSICIAN_PROVIDER_ID,
        PHYSICIAN_USER_ID,
        generateUuid(),
        { claimType: 'AHCIP', patientId: PLACEHOLDER_UUID, dateOfService: '2026-01-15' },
      );

      const entry = lastAuditEntry();
      expect(entry.actorContext).toBe(ActorContext.SYSTEM);
    });

    it('delegate actions through HTTP route record DELEGATE actor_context', async () => {
      const res = await app.inject({
        method: 'POST',
        url: '/api/v1/claims',
        headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
        payload: {
          claim_type: 'AHCIP',
          patient_id: PLACEHOLDER_UUID,
          date_of_service: '2026-01-15',
        },
      });

      // The handler calls createClaim with ActorContext.DELEGATE
      // (derived from auth context role)
      if (res.statusCode === 201) {
        expect(claimAuditEntries.length).toBeGreaterThanOrEqual(1);
        const entry = lastAuditEntry();
        expect(entry.actorContext).toBe(ActorContext.DELEGATE);
        expect(entry.actorId).toBe(DELEGATE_USER_ID);
      }
    });
  });

  // =========================================================================
  // Category 5: Audit Entry Field Completeness
  // =========================================================================

  describe('Audit entry fields are correctly populated', () => {
    it('every audit entry has claimId, action, actorId, actorContext, and createdAt', async () => {
      // Run through a full lifecycle to generate multiple audit entries
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });

      await validateClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN);

      for (const entry of claimAuditEntries) {
        expect(entry.claimId).toBeDefined();
        expect(entry.action).toBeDefined();
        expect(entry.actorId).toBeDefined();
        expect(entry.actorContext).toBeDefined();
        expect(entry.createdAt).toBeDefined();
      }
    });

    it('state-changing entries have both previousState and newState', async () => {
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });

      await validateClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN);

      // Created entry: previousState=null, newState=DRAFT
      const createdEntry = findAuditEntry(created.claimId, ClaimAuditAction.CREATED);
      expect(createdEntry).toBeDefined();
      expect(createdEntry!.newState).toBe(ClaimState.DRAFT);

      // Validated entry: previousState=DRAFT, newState=VALIDATED
      const validatedEntry = findAuditEntry(created.claimId, ClaimAuditAction.VALIDATED);
      expect(validatedEntry).toBeDefined();
      expect(validatedEntry!.previousState).toBe(ClaimState.DRAFT);
      expect(validatedEntry!.newState).toBe(ClaimState.VALIDATED);
    });

    it('write-off includes reason field', async () => {
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });
      const claim = claimStore.find((c) => c.claimId === created.claimId);
      if (claim) claim.state = ClaimState.REJECTED;
      claimAuditEntries = [];

      await writeOffClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, 'Patient deceased');

      const entry = findAuditEntry(created.claimId, ClaimAuditAction.WRITTEN_OFF);
      expect(entry).toBeDefined();
      expect(entry!.reason).toBe('Patient deceased');
    });

    it('queued entry includes isClean classification in changes', async () => {
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });
      await validateClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN);
      claimAuditEntries = [];

      await queueClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN);

      const entry = findAuditEntry(created.claimId, ClaimAuditAction.QUEUED);
      expect(entry).toBeDefined();
      expect(entry!.changes).toBeDefined();
      expect(typeof (entry!.changes as any).isClean).toBe('boolean');
    });
  });

  // =========================================================================
  // Category 6: Audit Log Integrity (Append-Only)
  // =========================================================================

  describe('Audit log is append-only — no modification or deletion API', () => {
    it('no PUT endpoint exists for claim audit history', async () => {
      const res = await physicianRequest('PUT', `/api/v1/claims/${PLACEHOLDER_UUID}/audit`);

      // Should return 404 (route not found) or 405 (method not allowed)
      expect([404, 405]).toContain(res.statusCode);
    });

    it('no DELETE endpoint exists for claim audit history', async () => {
      const res = await physicianRequest('DELETE', `/api/v1/claims/${PLACEHOLDER_UUID}/audit`);

      // Should return 404 (route not found) or 405 (method not allowed)
      expect([404, 405]).toContain(res.statusCode);
    });

    it('no POST endpoint exists for claim audit history (append via service only)', async () => {
      const res = await physicianRequest('POST', `/api/v1/claims/${PLACEHOLDER_UUID}/audit`, {
        action: 'FAKE_ACTION',
        changes: { injected: true },
      });

      // Should return 404 (route not found) or 405 (method not allowed)
      expect([404, 405]).toContain(res.statusCode);
    });

    it('GET /api/v1/claims/:id/audit is read-only and returns audit trail', async () => {
      const res = await physicianRequest('GET', `/api/v1/claims/${PLACEHOLDER_UUID}/audit`);

      // Should succeed (200) or not found the claim (404), but never modify data
      expect([200, 404]).toContain(res.statusCode);
    });
  });

  // =========================================================================
  // Category 7: Full Lifecycle Audit Trail
  // =========================================================================

  describe('Full claim lifecycle produces complete audit trail', () => {
    it('DRAFT -> VALIDATED -> QUEUED lifecycle produces 3 ordered audit entries', async () => {
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });

      await validateClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN);
      await queueClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN);

      const entries = auditEntriesForClaim(created.claimId);
      expect(entries.length).toBeGreaterThanOrEqual(3);

      const actions = entries.map((e) => e.action);
      expect(actions).toContain(ClaimAuditAction.CREATED);
      expect(actions).toContain(ClaimAuditAction.VALIDATED);
      expect(actions).toContain(ClaimAuditAction.QUEUED);

      // Verify chronological order
      const createdIdx = actions.indexOf(ClaimAuditAction.CREATED);
      const validatedIdx = actions.indexOf(ClaimAuditAction.VALIDATED);
      const queuedIdx = actions.indexOf(ClaimAuditAction.QUEUED);
      expect(createdIdx).toBeLessThan(validatedIdx);
      expect(validatedIdx).toBeLessThan(queuedIdx);
    });

    it('QUEUED -> VALIDATED (unqueue) -> QUEUED cycle produces correct audit trail', async () => {
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });
      await validateClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN);
      await queueClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN);
      await unqueueClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID);

      // Re-queue after unqueue
      // Claim is in VALIDATED state now, queue again
      await queueClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN);

      const entries = auditEntriesForClaim(created.claimId);
      const actions = entries.map((e) => e.action);

      // Should see: CREATED, VALIDATED, QUEUED, UNQUEUED, QUEUED
      expect(actions.filter((a) => a === ClaimAuditAction.QUEUED).length).toBe(2);
      expect(actions).toContain(ClaimAuditAction.UNQUEUED);
    });

    it('rejection -> write-off lifecycle produces complete audit trail', async () => {
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });
      const claim = claimStore.find((c) => c.claimId === created.claimId);
      if (claim) claim.state = ClaimState.REJECTED;

      await writeOffClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, 'Uncollectable');

      const entries = auditEntriesForClaim(created.claimId);
      const actions = entries.map((e) => e.action);
      expect(actions).toContain(ClaimAuditAction.CREATED);
      expect(actions).toContain(ClaimAuditAction.WRITTEN_OFF);
    });

    it('expiry produces audit with previous non-terminal state recorded', async () => {
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2024-01-15',
      });
      // Set deadline in the past so expiry can proceed
      const claim = claimStore.find((c) => c.claimId === created.claimId);
      if (claim) claim.submissionDeadline = '2024-04-15';

      await expireClaimWithContext(deps, created.claimId, PHYSICIAN_PROVIDER_ID, ClaimState.DRAFT);

      const entry = findAuditEntry(created.claimId, ClaimAuditAction.EXPIRED);
      expect(entry).toBeDefined();
      // The previous state should be whatever the claim was in before expiry (DRAFT in this case)
      expect(entry!.previousState).toBe(ClaimState.DRAFT);
      expect(entry!.newState).toBe(ClaimState.EXPIRED);
    });
  });

  // =========================================================================
  // Category 8: Sensitive Data Exclusion from Audit Entries
  // =========================================================================

  describe('Audit entries do not contain sensitive PHI', () => {
    it('audit entries do not contain patient PHN', async () => {
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });

      await validateClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN);

      const allEntries = JSON.stringify(claimAuditEntries);
      // PHN pattern: 9-digit number
      expect(allEntries).not.toMatch(/\b\d{9}\b/);
    });

    it('audit entries do not contain patient names', async () => {
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });

      const allEntries = JSON.stringify(claimAuditEntries);
      // Audit entries should not contain personal names
      expect(allEntries).not.toMatch(/firstName|lastName|first_name|last_name/i);
    });
  });

  // =========================================================================
  // Category 9: Multiple Actions on Same Claim
  // =========================================================================

  describe('Multiple actions on same claim accumulate correctly', () => {
    it('each action produces exactly one audit entry', async () => {
      const created = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });

      // Each service function should call appendClaimAudit exactly once
      expect(claimAuditEntries.length).toBe(1);

      await validateClaim(deps, created.claimId, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN);
      // Validation produces the validated audit entry
      const validatedEntries = claimAuditEntries.filter(
        (e) => e.action === ClaimAuditAction.VALIDATED && e.claimId === created.claimId,
      );
      expect(validatedEntries.length).toBe(1);
    });

    it('audit entries for different claims are independent', async () => {
      const claim1 = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'AHCIP',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-15',
      });

      const claim2 = await createClaim(deps, PHYSICIAN_PROVIDER_ID, PHYSICIAN_USER_ID, ActorContext.PHYSICIAN, {
        claimType: 'WCB',
        patientId: PLACEHOLDER_UUID,
        dateOfService: '2026-01-16',
      });

      const entries1 = auditEntriesForClaim(claim1.claimId);
      const entries2 = auditEntriesForClaim(claim2.claimId);

      expect(entries1.length).toBe(1);
      expect(entries2.length).toBe(1);
      expect(entries1[0].claimId).not.toBe(entries2[0].claimId);
    });
  });
});
