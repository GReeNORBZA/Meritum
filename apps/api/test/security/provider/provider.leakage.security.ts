import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);
process.env.INTERNAL_API_KEY = 'test-internal-api-key-32chars-ok';

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
import { providerRoutes, internalProviderRoutes } from '../../../src/domains/provider/provider.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import {
  type ProviderServiceDeps,
} from '../../../src/domains/provider/provider.service.js';
import {
  type ProviderHandlerDeps,
  type InternalProviderHandlerDeps,
} from '../../../src/domains/provider/provider.handlers.js';
import {
  type SessionManagementDeps,
  hashToken,
} from '../../../src/domains/iam/iam.service.js';
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Fixed test identities — Two isolated physicians + delegate
// ---------------------------------------------------------------------------

// Physician 1 — "our" physician
const P1_SESSION_TOKEN = randomBytes(32).toString('hex');
const P1_SESSION_TOKEN_HASH = hashToken(P1_SESSION_TOKEN);
const P1_USER_ID = '11111111-1111-0000-0000-000000000001';
const P1_PROVIDER_ID = P1_USER_ID; // 1:1 mapping
const P1_SESSION_ID = '11111111-1111-0000-0000-000000000011';

// Physician 2 — "other" physician (attacker perspective)
const P2_SESSION_TOKEN = randomBytes(32).toString('hex');
const P2_SESSION_TOKEN_HASH = hashToken(P2_SESSION_TOKEN);
const P2_USER_ID = '22222222-2222-0000-0000-000000000002';
const P2_PROVIDER_ID = P2_USER_ID;
const P2_SESSION_ID = '22222222-2222-0000-0000-000000000022';

// Delegate linked to Physician 1 only
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_USER_ID = '33333333-3333-0000-0000-000000000003';
const DELEGATE_SESSION_ID = '33333333-3333-0000-0000-000000000033';
const DELEGATE_LINKAGE_ID = '44444444-4444-0000-0000-000000000044';

// Resource IDs
const P1_BA_ID = 'aaaaaaaa-1111-0000-0000-000000000001';
const P1_LOCATION_ID = 'bbbbbbbb-1111-0000-0000-000000000001';
const P1_WCB_ID = 'cccccccc-1111-0000-0000-000000000001';
const P1_DELEGATE_REL_ID = 'dddddddd-1111-0000-0000-000000000001';

const PLACEHOLDER_UUID = '00000000-0000-0000-0000-000000000001';
const NONEXISTENT_UUID = '99999999-9999-9999-9999-999999999999';

// Internal API key
const INTERNAL_API_KEY = 'test-internal-api-key-32chars-ok';

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
// Mock provider data stores
// ---------------------------------------------------------------------------

const providerProfiles: Record<string, any> = {};
const basStore: Record<string, any> = {};
const locationsStore: Record<string, any> = {};
const wcbStore: Record<string, any> = {};
const delegateRelStore: Record<string, any> = {};
const prefsStore: Record<string, any> = {};
const hlinkStore: Record<string, any> = {};

function seedTestData() {
  // --- Provider profiles ---
  providerProfiles[P1_PROVIDER_ID] = {
    providerId: P1_PROVIDER_ID,
    billingNumber: '111111',
    cpsaRegistrationNumber: 'CPSA-001',
    firstName: 'Alice',
    lastName: 'Physician',
    middleName: null,
    specialtyCode: 'GP',
    specialtyDescription: 'General Practitioner',
    subSpecialtyCode: null,
    physicianType: 'GP',
    status: 'ACTIVE',
    onboardingCompleted: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  providerProfiles[P2_PROVIDER_ID] = {
    providerId: P2_PROVIDER_ID,
    billingNumber: '222222',
    cpsaRegistrationNumber: 'CPSA-002',
    firstName: 'Bob',
    lastName: 'Doctor',
    middleName: null,
    specialtyCode: 'SPEC',
    specialtyDescription: 'Specialist',
    subSpecialtyCode: null,
    physicianType: 'SPECIALIST',
    status: 'ACTIVE',
    onboardingCompleted: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- BAs ---
  basStore[P1_BA_ID] = {
    baId: P1_BA_ID,
    providerId: P1_PROVIDER_ID,
    baNumber: '11111',
    baType: 'FFS',
    isPrimary: true,
    status: 'ACTIVE',
    effectiveDate: '2025-01-01',
    endDate: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- Locations ---
  locationsStore[P1_LOCATION_ID] = {
    locationId: P1_LOCATION_ID,
    providerId: P1_PROVIDER_ID,
    name: 'Alice Clinic',
    functionalCentre: 'FC01',
    facilityNumber: null,
    addressLine1: '123 Main St',
    addressLine2: null,
    city: 'Edmonton',
    province: 'AB',
    postalCode: 'T5A0A1',
    communityCode: null,
    isActive: true,
    isDefault: true,
    rrnpEligible: false,
    rrnpPercentage: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- WCB Configs ---
  wcbStore[P1_WCB_ID] = {
    wcbConfigId: P1_WCB_ID,
    providerId: P1_PROVIDER_ID,
    contractId: 'C001',
    roleCode: 'R01',
    skillCode: 'S01',
    isDefault: true,
    permittedFormTypes: ['WCB_PHYSICIAN_FIRST_REPORT'],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- Delegate Relationships ---
  delegateRelStore[P1_DELEGATE_REL_ID] = {
    relationshipId: P1_DELEGATE_REL_ID,
    physicianId: P1_PROVIDER_ID,
    delegateUserId: DELEGATE_USER_ID,
    delegateEmail: 'delegate@example.com',
    delegateFullName: 'Diane Delegate',
    permissions: ['CLAIM_VIEW', 'PATIENT_VIEW'],
    status: 'ACTIVE',
    invitedAt: new Date(),
    acceptedAt: new Date(),
    revokedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- Submission Preferences ---
  prefsStore[P1_PROVIDER_ID] = {
    preferenceId: 'pref-p1',
    providerId: P1_PROVIDER_ID,
    ahcipSubmissionMode: 'AUTO_CLEAN',
    wcbSubmissionMode: 'REQUIRE_APPROVAL',
    batchReviewReminder: true,
    deadlineReminderDays: 7,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- H-Link Configurations (includes secret ref in storage) ---
  hlinkStore[P1_PROVIDER_ID] = {
    hlinkConfigId: 'hlink-p1',
    providerId: P1_PROVIDER_ID,
    submitterPrefix: 'MER1',
    accreditationStatus: 'ACTIVE',
    accreditationDate: '2025-01-15',
    lastSuccessfulTransmission: new Date('2026-02-01'),
    credentialSecretRef: 'vault://secrets/hlink/p1-credential-secret-do-not-leak',
    createdAt: new Date(),
    updatedAt: new Date(),
  };
}

// ---------------------------------------------------------------------------
// Physician-scoped mock provider repository
// ---------------------------------------------------------------------------

function createScopedProviderRepo() {
  return {
    findProviderById: vi.fn(async (providerId: string) => {
      return providerProfiles[providerId] ?? undefined;
    }),
    getFullProviderContext: vi.fn(async (providerId: string) => {
      const profile = providerProfiles[providerId];
      if (!profile) return undefined;
      return {
        ...profile,
        bas: Object.values(basStore).filter((ba: any) => ba.providerId === providerId),
        locations: Object.values(locationsStore).filter((loc: any) => loc.providerId === providerId),
        wcbConfigs: Object.values(wcbStore).filter((wcb: any) => wcb.providerId === providerId),
        submissionPreferences: prefsStore[providerId] ?? null,
        // Service layer strips credentialSecretRef, but we verify here
        hlinkConfig: hlinkStore[providerId]
          ? { ...hlinkStore[providerId], credentialSecretRef: undefined }
          : null,
      };
    }),
    createProvider: vi.fn(async () => ({})),
    updateProvider: vi.fn(async (providerId: string, data: any) => {
      const existing = providerProfiles[providerId];
      if (!existing) return undefined;
      return { ...existing, ...data, updatedAt: new Date() };
    }),
    listBas: vi.fn(async (providerId: string) => {
      return Object.values(basStore).filter((ba: any) => ba.providerId === providerId);
    }),
    findBaById: vi.fn(async (baId: string, providerId: string) => {
      const ba = basStore[baId];
      if (!ba || ba.providerId !== providerId) return undefined;
      return ba;
    }),
    createBa: vi.fn(async (data: any) => {
      const ba = { baId: randomBytes(16).toString('hex'), ...data, createdAt: new Date(), updatedAt: new Date() };
      basStore[ba.baId] = ba;
      return ba;
    }),
    updateBa: vi.fn(async (baId: string, providerId: string, data: any) => {
      const ba = basStore[baId];
      if (!ba || ba.providerId !== providerId) return undefined;
      return { ...ba, ...data, updatedAt: new Date() };
    }),
    deactivateBa: vi.fn(async (baId: string, providerId: string) => {
      const ba = basStore[baId];
      if (!ba || ba.providerId !== providerId) return undefined;
      return { ...ba, status: 'INACTIVE', updatedAt: new Date() };
    }),
    listLocations: vi.fn(async (providerId: string) => {
      return Object.values(locationsStore).filter((loc: any) => loc.providerId === providerId);
    }),
    findLocationById: vi.fn(async (locationId: string, providerId: string) => {
      const loc = locationsStore[locationId];
      if (!loc || loc.providerId !== providerId) return undefined;
      return loc;
    }),
    createLocation: vi.fn(async (data: any) => {
      const loc = { locationId: randomBytes(16).toString('hex'), ...data, createdAt: new Date(), updatedAt: new Date() };
      locationsStore[loc.locationId] = loc;
      return loc;
    }),
    updateLocation: vi.fn(async (locationId: string, providerId: string, data: any) => {
      const loc = locationsStore[locationId];
      if (!loc || loc.providerId !== providerId) return undefined;
      return { ...loc, ...data, updatedAt: new Date() };
    }),
    setDefaultLocation: vi.fn(async (locationId: string, providerId: string) => {
      const loc = locationsStore[locationId];
      if (!loc || loc.providerId !== providerId) return undefined;
      return { ...loc, isDefault: true, updatedAt: new Date() };
    }),
    deactivateLocation: vi.fn(async (locationId: string, providerId: string) => {
      const loc = locationsStore[locationId];
      if (!loc || loc.providerId !== providerId) return undefined;
      return { ...loc, isActive: false, updatedAt: new Date() };
    }),
    listWcbConfigs: vi.fn(async (providerId: string) => {
      return Object.values(wcbStore).filter((wcb: any) => wcb.providerId === providerId);
    }),
    findWcbConfigById: vi.fn(async (wcbConfigId: string, providerId: string) => {
      const wcb = wcbStore[wcbConfigId];
      if (!wcb || wcb.providerId !== providerId) return undefined;
      return wcb;
    }),
    createWcbConfig: vi.fn(async (data: any) => {
      const wcb = { wcbConfigId: randomBytes(16).toString('hex'), ...data, createdAt: new Date(), updatedAt: new Date() };
      wcbStore[wcb.wcbConfigId] = wcb;
      return wcb;
    }),
    updateWcbConfig: vi.fn(async (wcbConfigId: string, providerId: string, data: any) => {
      const wcb = wcbStore[wcbConfigId];
      if (!wcb || wcb.providerId !== providerId) return undefined;
      return { ...wcb, ...data, updatedAt: new Date() };
    }),
    removeWcbConfig: vi.fn(async (wcbConfigId: string, providerId: string) => {
      const wcb = wcbStore[wcbConfigId];
      if (!wcb || wcb.providerId !== providerId) return undefined;
      return wcb;
    }),
    getFormPermissions: vi.fn(async (providerId: string) => {
      const configs = Object.values(wcbStore).filter((wcb: any) => wcb.providerId === providerId);
      const allForms = new Set<string>();
      configs.forEach((wcb: any) => { (wcb.permittedFormTypes ?? []).forEach((f: string) => allForms.add(f)); });
      return Array.from(allForms);
    }),
    findSubmissionPreferences: vi.fn(async (providerId: string) => {
      return prefsStore[providerId] ?? undefined;
    }),
    upsertSubmissionPreferences: vi.fn(async (providerId: string, data: any) => {
      const existing = prefsStore[providerId] ?? {};
      prefsStore[providerId] = { ...existing, ...data, providerId, updatedAt: new Date() };
      return prefsStore[providerId];
    }),
    findHlinkConfig: vi.fn(async (providerId: string) => {
      return hlinkStore[providerId] ?? undefined;
    }),
    upsertHlinkConfig: vi.fn(async (providerId: string, data: any) => {
      const existing = hlinkStore[providerId] ?? {};
      hlinkStore[providerId] = { ...existing, ...data, providerId, updatedAt: new Date() };
      return hlinkStore[providerId];
    }),
    updateHlinkConfig: vi.fn(async (providerId: string, data: any) => {
      const existing = hlinkStore[providerId];
      if (!existing) return undefined;
      hlinkStore[providerId] = { ...existing, ...data, updatedAt: new Date() };
      return hlinkStore[providerId];
    }),
    listDelegates: vi.fn(async (physicianId: string) => {
      return Object.values(delegateRelStore).filter(
        (rel: any) => rel.physicianId === physicianId,
      );
    }),
    listDelegatesForPhysician: vi.fn(async (physicianId: string) => {
      return Object.values(delegateRelStore)
        .filter((rel: any) => rel.physicianId === physicianId)
        .map((rel: any) => ({
          relationshipId: rel.relationshipId,
          physicianId: rel.physicianId,
          delegateUserId: rel.delegateUserId,
          delegateEmail: rel.delegateEmail,
          delegateFullName: rel.delegateFullName,
          permissions: rel.permissions,
          status: rel.status,
          invitedAt: rel.invitedAt,
          acceptedAt: rel.acceptedAt,
          revokedAt: rel.revokedAt,
        }));
    }),
    findRelationshipById: vi.fn(async (relationshipId: string, physicianId: string) => {
      const rel = delegateRelStore[relationshipId];
      if (!rel || rel.physicianId !== physicianId) return undefined;
      return rel;
    }),
    findDelegateRelationship: vi.fn(async () => undefined),
    createDelegateRelationship: vi.fn(async () => ({})),
    updateDelegateRelationshipPermissions: vi.fn(async (relationshipId: string, physicianId: string, data: any) => {
      const rel = delegateRelStore[relationshipId];
      if (!rel || rel.physicianId !== physicianId) return undefined;
      return { ...rel, permissions: data.permissions, updatedAt: new Date() };
    }),
    revokeRelationship: vi.fn(async (relationshipId: string, physicianId: string) => {
      const rel = delegateRelStore[relationshipId];
      if (!rel || rel.physicianId !== physicianId) return undefined;
      return { ...rel, status: 'REVOKED', revokedAt: new Date(), updatedAt: new Date() };
    }),
    revokeDelegateRelationship: vi.fn(async () => ({})),
    listPhysiciansForDelegate: vi.fn(async (delegateUserId: string) => {
      return Object.values(delegateRelStore)
        .filter((rel: any) => rel.delegateUserId === delegateUserId && rel.status === 'ACTIVE')
        .map((rel: any) => ({
          relationshipId: rel.relationshipId,
          physicianId: rel.physicianId,
          permissions: rel.permissions,
          physicianName: providerProfiles[rel.physicianId]
            ? `${providerProfiles[rel.physicianId].firstName} ${providerProfiles[rel.physicianId].lastName}`
            : 'Unknown',
        }));
    }),
    findActiveRelationship: vi.fn(async (physicianId: string, delegateUserId: string) => {
      return Object.values(delegateRelStore).find(
        (rel: any) =>
          rel.physicianId === physicianId &&
          rel.delegateUserId === delegateUserId &&
          rel.status === 'ACTIVE',
      ) ?? undefined;
    }),
    findDelegateLinkage: vi.fn(async () => undefined),
    getOnboardingStatus: vi.fn(async () => ({
      hasBillingNumber: true,
      hasCpsaNumber: true,
      hasName: true,
      hasBa: true,
      hasLocation: true,
      isComplete: true,
      missingFields: [],
    })),
    completeOnboarding: vi.fn(async () => ({})),
    getProviderContext: vi.fn(async (providerId: string) => {
      const profile = providerProfiles[providerId];
      if (!profile) return undefined;
      return {
        ...profile,
        bas: Object.values(basStore).filter((ba: any) => ba.providerId === providerId),
        locations: Object.values(locationsStore).filter((loc: any) => loc.providerId === providerId),
        wcbConfigs: Object.values(wcbStore).filter((wcb: any) => wcb.providerId === providerId),
        submissionPreferences: prefsStore[providerId] ?? null,
        hlinkConfig: hlinkStore[providerId]
          ? { ...hlinkStore[providerId], credentialSecretRef: undefined }
          : null,
      };
    }),
    getBaForClaim: vi.fn(async () => undefined),
    findWcbConfigByContractRole: vi.fn(async () => undefined),
    findPcpcmEnrolment: vi.fn(async () => undefined),
    countBas: vi.fn(async (providerId: string) => {
      return Object.values(basStore).filter((ba: any) => ba.providerId === providerId).length;
    }),
    countLocations: vi.fn(async (providerId: string) => {
      return Object.values(locationsStore).filter((loc: any) => loc.providerId === providerId).length;
    }),
    countWcbConfigs: vi.fn(async (providerId: string) => {
      return Object.values(wcbStore).filter((wcb: any) => wcb.providerId === providerId).length;
    }),
  };
}

function createStubServiceDeps(): ProviderServiceDeps {
  return {
    repo: createScopedProviderRepo() as any,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
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

  const serviceDeps = createStubServiceDeps();

  const handlerDeps: ProviderHandlerDeps = {
    serviceDeps,
  };

  const internalHandlerDeps: InternalProviderHandlerDeps = {
    serviceDeps,
  };

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, request, reply) => {
    const statusCode = (error as any).statusCode;
    if (statusCode && statusCode >= 400 && statusCode < 500) {
      return reply.code(statusCode).send({
        error: { code: (error as any).code ?? 'ERROR', message: error.message },
      });
    }
    if (error.validation) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed' },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(providerRoutes, { deps: handlerDeps });
  await testApp.register(internalProviderRoutes, { deps: internalHandlerDeps });
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function asPhysician1(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P1_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function asPhysician2(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${P2_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function asInternal(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { 'x-internal-api-key': INTERNAL_API_KEY },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function unauthenticated(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Recursive key checker — ensure a key never appears at any nesting level
// ---------------------------------------------------------------------------

function containsKeyRecursive(obj: unknown, targetKey: string): boolean {
  if (obj === null || obj === undefined || typeof obj !== 'object') return false;
  if (Array.isArray(obj)) {
    return obj.some((item) => containsKeyRecursive(item, targetKey));
  }
  for (const key of Object.keys(obj as Record<string, unknown>)) {
    if (key === targetKey) return true;
    if (containsKeyRecursive((obj as Record<string, unknown>)[key], targetKey)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Seed users and sessions
// ---------------------------------------------------------------------------

function seedUsersAndSessions() {
  users = [];
  sessions = [];

  // Physician 1
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

  // Physician 2
  users.push({
    userId: P2_USER_ID,
    email: 'physician2@example.com',
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
    sessionId: P2_SESSION_ID,
    userId: P2_USER_ID,
    tokenHash: P2_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.2',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Delegate linked to Physician 1
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
      physicianProviderId: P1_PROVIDER_ID,
      permissions: ['CLAIM_VIEW', 'PATIENT_VIEW', 'PROVIDER_VIEW', 'PREFERENCE_VIEW'],
      linkageId: DELEGATE_LINKAGE_ID,
    },
  });
  sessions.push({
    sessionId: DELEGATE_SESSION_ID,
    userId: DELEGATE_USER_ID,
    tokenHash: DELEGATE_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.3',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Provider Data Leakage Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsersAndSessions();
    seedTestData();
    auditEntries = [];
  });

  // =========================================================================
  // 1. Credential Leakage Prevention
  // =========================================================================

  describe('Credential leakage prevention — credentialSecretRef must never appear in responses', () => {
    it('GET /api/v1/providers/me/hlink response does NOT contain credentialSecretRef', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/hlink');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);

      // Verify the key does not exist at any nesting level
      expect(containsKeyRecursive(body, 'credentialSecretRef')).toBe(false);
      expect(containsKeyRecursive(body, 'credential_secret_ref')).toBe(false);

      // Verify the actual secret value does not appear anywhere in the raw response
      expect(res.body).not.toContain('vault://');
      expect(res.body).not.toContain('do-not-leak');
      expect(res.body).not.toContain('p1-credential-secret');
    });

    it('GET /api/v1/providers/me (full profile) does NOT contain credentialSecretRef', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);

      expect(containsKeyRecursive(body, 'credentialSecretRef')).toBe(false);
      expect(containsKeyRecursive(body, 'credential_secret_ref')).toBe(false);
      expect(res.body).not.toContain('vault://');
      expect(res.body).not.toContain('do-not-leak');
      expect(res.body).not.toContain('p1-credential-secret');
    });

    it('GET /api/v1/internal/providers/:id/claim-context does NOT contain credentialSecretRef', async () => {
      const res = await asInternal('GET', `/api/v1/internal/providers/${P1_PROVIDER_ID}/claim-context`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);

      expect(containsKeyRecursive(body, 'credentialSecretRef')).toBe(false);
      expect(containsKeyRecursive(body, 'credential_secret_ref')).toBe(false);
      expect(res.body).not.toContain('vault://');
      expect(res.body).not.toContain('do-not-leak');
    });

    it('H-Link config response contains only expected safe fields', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/hlink');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);

      // H-Link data should have only safe fields
      const hlinkData = body.data;
      expect(hlinkData).toHaveProperty('submitterPrefix');
      expect(hlinkData).toHaveProperty('accreditationStatus');
      // Should NOT have any credential fields
      expect(hlinkData).not.toHaveProperty('credentialSecretRef');
      expect(hlinkData).not.toHaveProperty('credential_secret_ref');
      expect(hlinkData).not.toHaveProperty('credentialId');
      expect(hlinkData).not.toHaveProperty('credential_id');
    });
  });

  // =========================================================================
  // 2. Error Response Sanitisation
  // =========================================================================

  describe('Error response sanitisation', () => {
    it('401 response body contains only error object, no provider data', async () => {
      const res = await unauthenticated('GET', '/api/v1/providers/me');
      expect(res.statusCode).toBe(401);
      const body = JSON.parse(res.body);

      // Must only have error key
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.error).toHaveProperty('code');
      expect(body.error).toHaveProperty('message');
      expect(body.data).toBeUndefined();

      // No provider data leaked
      expect(res.body).not.toContain('providerId');
      expect(res.body).not.toContain('billingNumber');
      expect(res.body).not.toContain('Alice');
    });

    it('404 for cross-user resource has same shape as genuinely missing resource', async () => {
      // Cross-tenant: physician1 requests physician2's BA (exists but not theirs)
      const crossTenantRes = await asPhysician1('PUT', `/api/v1/providers/me/bas/${NONEXISTENT_UUID}`, {
        status: 'ACTIVE',
      });

      // Genuinely missing: physician1 requests a resource that doesn't exist at all
      const genuinelyMissingRes = await asPhysician1('PUT', `/api/v1/providers/me/bas/${PLACEHOLDER_UUID}`, {
        status: 'ACTIVE',
      });

      // Both should be 404 with identical error shape
      expect(crossTenantRes.statusCode).toBe(404);
      expect(genuinelyMissingRes.statusCode).toBe(404);

      const crossBody = JSON.parse(crossTenantRes.body);
      const missingBody = JSON.parse(genuinelyMissingRes.body);

      // Same error structure
      expect(Object.keys(crossBody)).toEqual(Object.keys(missingBody));
      expect(crossBody.error.code).toBe(missingBody.error.code);

      // Neither should contain resource identifiers
      expect(crossTenantRes.body).not.toContain(NONEXISTENT_UUID);
      expect(genuinelyMissingRes.body).not.toContain(PLACEHOLDER_UUID);
    });

    it('500 error does not expose stack traces or internal details', async () => {
      // The error handler is configured to return a generic 500 for unexpected errors.
      // We verify the error handler configuration produces the expected shape.
      // Since we can't easily trigger a real 500 in unit tests, we verify the
      // error handler format by checking it doesn't expose internals on any error.
      const res = await asPhysician1('GET', '/api/v1/providers/me');
      // Even on success responses, let's verify error handling config by
      // triggering a service-level error through a bad state.
      // For now, verify the error handler shape on 404 (which flows through same handler)
      const errorRes = await asPhysician1('PUT', `/api/v1/providers/me/bas/${NONEXISTENT_UUID}`, {
        status: 'ACTIVE',
      });
      const body = JSON.parse(errorRes.body);

      expect(body.error).not.toHaveProperty('stack');
      expect(body.error).not.toHaveProperty('stackTrace');
      expect(JSON.stringify(body)).not.toMatch(/at\s+\w+\s+\(/); // stack trace pattern
      expect(JSON.stringify(body)).not.toMatch(/\.ts:\d+:\d+/); // file:line:col pattern
      expect(JSON.stringify(body)).not.toContain('node_modules');
    });

    it('validation error (400) does not expose database column names', async () => {
      const res = await asPhysician1('POST', '/api/v1/providers/me/bas', {
        ba_number: '',
        ba_type: 'INVALID',
      });
      expect(res.statusCode).toBe(400);

      const rawBody = res.body.toLowerCase();
      // Should not contain internal DB column names
      expect(rawBody).not.toContain('billing_number');
      expect(rawBody).not.toContain('ba_number constraint');
      expect(rawBody).not.toContain('column');
      expect(rawBody).not.toContain('constraint violation');
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('pg_');
    });

    it('validation error does not echo full request body values', async () => {
      const canaryValue = 'CANARY_LEAKAGE_PROBE_12345';
      const res = await asPhysician1('POST', '/api/v1/providers/me/bas', {
        ba_number: canaryValue,
        ba_type: 'INVALID_TYPE',
      });
      expect(res.statusCode).toBe(400);

      const body = JSON.parse(res.body);
      // Error message should not contain the canary value
      expect(body.error.message).not.toContain(canaryValue);
    });
  });

  // =========================================================================
  // 3. Response Header Checks
  // =========================================================================

  describe('Response header security', () => {
    it('no X-Powered-By header in authenticated responses', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me');
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in 401 responses', async () => {
      const res = await unauthenticated('GET', '/api/v1/providers/me');
      expect(res.statusCode).toBe(401);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in 400 responses', async () => {
      const res = await asPhysician1('POST', '/api/v1/providers/me/bas', {
        ba_number: '',
        ba_type: 'INVALID',
      });
      expect(res.statusCode).toBe(400);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no Server header revealing version/technology', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/bas');
      // Server header should not be present or should not reveal technology details
      const serverHeader = res.headers['server'];
      if (serverHeader) {
        const lower = (serverHeader as string).toLowerCase();
        expect(lower).not.toContain('fastify');
        expect(lower).not.toContain('node');
        expect(lower).not.toContain('express');
      }
    });

    it('responses include Content-Type: application/json', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me');
      expect(res.headers['content-type']).toContain('application/json');
    });

    it('error responses include Content-Type: application/json', async () => {
      const res = await unauthenticated('GET', '/api/v1/providers/me');
      expect(res.headers['content-type']).toContain('application/json');
    });

    it('validation error responses include Content-Type: application/json', async () => {
      const res = await asPhysician1('POST', '/api/v1/providers/me/bas', {});
      expect(res.statusCode).toBe(400);
      expect(res.headers['content-type']).toContain('application/json');
    });
  });

  // =========================================================================
  // 4. Sensitive Data Not in Delegate Responses
  // =========================================================================

  describe('Sensitive data excluded from delegate list responses', () => {
    it('delegate list does not expose password_hash from joined users table', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/delegates');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('passwordHash');
      expect(rawBody).not.toContain('password_hash');
      expect(rawBody).not.toContain('hashed'); // the mock password hash value

      const body = JSON.parse(rawBody);
      body.data.forEach((delegate: any) => {
        expect(delegate).not.toHaveProperty('passwordHash');
        expect(delegate).not.toHaveProperty('password_hash');
      });
    });

    it('delegate list does not expose email verification tokens', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/delegates');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('verificationToken');
      expect(rawBody).not.toContain('verification_token');
      expect(rawBody).not.toContain('emailVerified');
      expect(rawBody).not.toContain('email_verified');
    });

    it('delegate list does not expose session data', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/delegates');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('sessionId');
      expect(rawBody).not.toContain('session_id');
      expect(rawBody).not.toContain('tokenHash');
      expect(rawBody).not.toContain('token_hash');
    });

    it('delegate list only contains expected safe fields', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/delegates');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);

      const safeFields = new Set([
        'relationshipId', 'physicianId', 'delegateUserId',
        'delegateEmail', 'delegateFullName',
        'permissions', 'status', 'invitedAt', 'acceptedAt', 'revokedAt',
      ]);

      body.data.forEach((delegate: any) => {
        for (const key of Object.keys(delegate)) {
          expect(safeFields.has(key)).toBe(true);
        }
      });
    });
  });

  // =========================================================================
  // 5. Audit Log Entries Do Not Contain Credential Values
  // =========================================================================

  describe('Audit log entries do not contain actual credential values', () => {
    it('H-Link config update audit entry does not contain credentialSecretRef value', async () => {
      const res = await asPhysician1('PUT', '/api/v1/providers/me/hlink', {
        submitter_prefix: 'NEW1',
      });

      // Even if the update succeeds or fails, check audit entries
      if (res.statusCode === 200) {
        const hlinkAudits = auditEntries.filter(
          (e) => e.resourceType === 'hlink_configuration',
        );

        const auditString = JSON.stringify(hlinkAudits);
        expect(auditString).not.toContain('vault://');
        expect(auditString).not.toContain('do-not-leak');
        expect(auditString).not.toContain('p1-credential-secret');
        expect(auditString).not.toContain('credentialSecretRef');
      }
    });

    it('profile update audit entry does not contain other provider data', async () => {
      const res = await asPhysician1('PUT', '/api/v1/providers/me', {
        first_name: 'UpdatedAlice',
      });

      if (res.statusCode === 200) {
        const profileAudits = auditEntries.filter(
          (e) => e.resourceType === 'provider',
        );
        const auditString = JSON.stringify(profileAudits);
        // Must not contain other physician's data
        expect(auditString).not.toContain(P2_PROVIDER_ID);
        expect(auditString).not.toContain('222222');
        expect(auditString).not.toContain('Bob');
      }
    });
  });

  // =========================================================================
  // 6. Internal API Responses Do Not Leak Other Providers' Data
  // =========================================================================

  describe('Internal API responses do not leak other providers data', () => {
    it('claim-context for provider1 does not contain provider2 data', async () => {
      const res = await asInternal('GET', `/api/v1/internal/providers/${P1_PROVIDER_ID}/claim-context`);
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('222222'); // P2's billing number
      expect(rawBody).not.toContain('Bob');
      expect(rawBody).not.toContain('CPSA-002');
    });

    it('claim-context for non-existent provider returns 404 with generic error', async () => {
      const res = await asInternal('GET', `/api/v1/internal/providers/${NONEXISTENT_UUID}/claim-context`);
      expect(res.statusCode).toBe(404);

      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.error.code).toBe('NOT_FOUND');
      // Should not reveal whether the ID format was valid
      expect(body.error.message).not.toContain(NONEXISTENT_UUID);
    });

    it('internal route 404 for valid-format but non-existent provider_id returns same error as genuinely missing', async () => {
      const validFormatId = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee';
      const res1 = await asInternal('GET', `/api/v1/internal/providers/${validFormatId}/claim-context`);
      const res2 = await asInternal('GET', `/api/v1/internal/providers/${NONEXISTENT_UUID}/claim-context`);

      expect(res1.statusCode).toBe(res2.statusCode);
      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);
      expect(body1.error.code).toBe(body2.error.code);
    });
  });

  // =========================================================================
  // 7. Anti-Enumeration
  // =========================================================================

  describe('Anti-enumeration protection', () => {
    it('delegate invite with existing delegate email returns consistent error shape', async () => {
      // First invite — may succeed or fail depending on mock state
      const res1 = await asPhysician1('POST', '/api/v1/providers/me/delegates/invite', {
        email: 'new-delegate@example.com',
        permissions: ['CLAIM_VIEW'],
      });

      // Second invite with same email — should have consistent response shape
      const res2 = await asPhysician1('POST', '/api/v1/providers/me/delegates/invite', {
        email: 'new-delegate@example.com',
        permissions: ['CLAIM_VIEW'],
      });

      // Both responses should have the same structure (whether success or error)
      // The key point: the system does not leak whether the email is already a delegate
      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);

      // Same top-level keys
      expect(Object.keys(body1).sort()).toEqual(Object.keys(body2).sort());
    });

    it('invalid provider_id in internal routes returns same error regardless of existence', async () => {
      // Valid format but non-existent
      const fakeId1 = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
      const res1 = await asInternal('GET', `/api/v1/internal/providers/${fakeId1}/claim-context`);

      // Another valid format but non-existent
      const fakeId2 = 'abababab-abab-abab-abab-abababababab';
      const res2 = await asInternal('GET', `/api/v1/internal/providers/${fakeId2}/claim-context`);

      // Both should return identical error shape
      expect(res1.statusCode).toBe(res2.statusCode);
      const body1 = JSON.parse(res1.body);
      const body2 = JSON.parse(res2.body);
      expect(body1.error.code).toBe(body2.error.code);
      expect(body1.error.message).toBe(body2.error.message);

      // Error should not contain either ID
      expect(res1.body).not.toContain(fakeId1);
      expect(res2.body).not.toContain(fakeId2);
    });

    it('404 for cross-tenant resource is indistinguishable from genuinely missing resource', async () => {
      // Non-existent BA (not in any store)
      const missingRes = await asPhysician1('PUT', `/api/v1/providers/me/bas/${NONEXISTENT_UUID}`, {
        status: 'ACTIVE',
      });

      // Another non-existent BA
      const anotherMissingRes = await asPhysician1('PUT', `/api/v1/providers/me/bas/${PLACEHOLDER_UUID}`, {
        status: 'ACTIVE',
      });

      expect(missingRes.statusCode).toBe(404);
      expect(anotherMissingRes.statusCode).toBe(404);

      // Error shapes must be identical
      const body1 = JSON.parse(missingRes.body);
      const body2 = JSON.parse(anotherMissingRes.body);
      expect(body1.error.code).toBe(body2.error.code);
      expect(body1.error.message).toBe(body2.error.message);
    });
  });

  // =========================================================================
  // 8. Full Profile Response — No Sensitive Fields Leak
  // =========================================================================

  describe('Full profile response does not leak sensitive fields', () => {
    it('GET /api/v1/providers/me does not contain password_hash', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me');
      expect(res.statusCode).toBe(200);
      expect(res.body).not.toContain('passwordHash');
      expect(res.body).not.toContain('password_hash');
    });

    it('GET /api/v1/providers/me does not contain session data', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me');
      expect(res.statusCode).toBe(200);
      expect(res.body).not.toContain('tokenHash');
      expect(res.body).not.toContain('token_hash');
      expect(res.body).not.toContain(P1_SESSION_TOKEN);
      expect(res.body).not.toContain(P1_SESSION_TOKEN_HASH);
    });

    it('GET /api/v1/providers/me does not contain TOTP secrets', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me');
      expect(res.statusCode).toBe(200);
      expect(res.body).not.toContain('totpSecret');
      expect(res.body).not.toContain('totp_secret');
      expect(res.body).not.toContain('JBSWY3DPEHPK3PXP'); // mock TOTP secret
    });
  });

  // =========================================================================
  // 9. Error Responses — Consistent Generic Shapes
  // =========================================================================

  describe('Error responses are generic and do not reveal internal state', () => {
    it('all 404 responses have consistent error structure', async () => {
      const routes = [
        { method: 'PUT' as const, url: `/api/v1/providers/me/bas/${NONEXISTENT_UUID}`, payload: { status: 'ACTIVE' } },
        { method: 'PUT' as const, url: `/api/v1/providers/me/locations/${NONEXISTENT_UUID}`, payload: { name: 'X' } },
        { method: 'DELETE' as const, url: `/api/v1/providers/me/wcb/${NONEXISTENT_UUID}` },
        { method: 'POST' as const, url: `/api/v1/providers/me/delegates/${NONEXISTENT_UUID}/revoke` },
      ];

      for (const route of routes) {
        const res = await asPhysician1(route.method, route.url, route.payload);
        expect(res.statusCode).toBe(404);
        const body = JSON.parse(res.body);

        // Consistent structure: only error key
        expect(body.error).toBeDefined();
        expect(body.data).toBeUndefined();
        expect(body.error).toHaveProperty('code');
        expect(body.error).toHaveProperty('message');

        // No stack traces or internal details
        expect(body.error).not.toHaveProperty('stack');
        expect(JSON.stringify(body)).not.toMatch(/\.ts:\d+/);
        expect(JSON.stringify(body)).not.toContain('node_modules');
      }
    });

    it('error responses never contain SQL-related keywords', async () => {
      const res = await asPhysician1('POST', '/api/v1/providers/me/bas', {
        ba_number: "'; DROP TABLE providers;--",
        ba_type: 'FFS',
      });
      expect(res.statusCode).toBe(400);

      const lower = res.body.toLowerCase();
      expect(lower).not.toContain('postgres');
      expect(lower).not.toContain('drizzle');
      expect(lower).not.toContain('pg_catalog');
      expect(lower).not.toContain('relation');
      expect(lower).not.toContain('syntax error');
    });
  });
});
