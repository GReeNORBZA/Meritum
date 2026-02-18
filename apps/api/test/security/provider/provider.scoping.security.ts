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
import { providerRoutes } from '../../../src/domains/provider/provider.routes.js';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import {
  type ProviderServiceDeps,
} from '../../../src/domains/provider/provider.service.js';
import { type ProviderHandlerDeps } from '../../../src/domains/provider/provider.handlers.js';
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

// ---------------------------------------------------------------------------
// Test data IDs — resources owned by each physician
// ---------------------------------------------------------------------------

// Physician 1's resources
const P1_BA_ID = 'aaaaaaaa-1111-0000-0000-000000000001';
const P1_LOCATION_ID = 'bbbbbbbb-1111-0000-0000-000000000001';
const P1_WCB_ID = 'cccccccc-1111-0000-0000-000000000001';
const P1_DELEGATE_REL_ID = 'dddddddd-1111-0000-0000-000000000001';

// Physician 2's resources
const P2_BA_ID = 'aaaaaaaa-2222-0000-0000-000000000002';
const P2_LOCATION_ID = 'bbbbbbbb-2222-0000-0000-000000000002';
const P2_WCB_ID = 'cccccccc-2222-0000-0000-000000000002';
const P2_DELEGATE_REL_ID = 'dddddddd-2222-0000-0000-000000000002';

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
    appendAuditLog: vi.fn(async () => {}),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Mock provider data stores (physician-scoped)
// ---------------------------------------------------------------------------

// Provider profiles
const providerProfiles: Record<string, any> = {};

// BAs keyed by baId, each has a providerId
const basStore: Record<string, any> = {};

// Locations keyed by locationId
const locationsStore: Record<string, any> = {};

// WCB configs keyed by wcbConfigId
const wcbStore: Record<string, any> = {};

// Delegate relationships keyed by relationshipId
const delegateRelStore: Record<string, any> = {};

// Submission preferences keyed by providerId
const prefsStore: Record<string, any> = {};

// H-Link configurations keyed by providerId
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
  basStore[P2_BA_ID] = {
    baId: P2_BA_ID,
    providerId: P2_PROVIDER_ID,
    baNumber: '22222',
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
  locationsStore[P2_LOCATION_ID] = {
    locationId: P2_LOCATION_ID,
    providerId: P2_PROVIDER_ID,
    name: 'Bob Clinic',
    functionalCentre: 'FC02',
    facilityNumber: null,
    addressLine1: '456 Oak Ave',
    addressLine2: null,
    city: 'Calgary',
    province: 'AB',
    postalCode: 'T2P1A1',
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
  wcbStore[P2_WCB_ID] = {
    wcbConfigId: P2_WCB_ID,
    providerId: P2_PROVIDER_ID,
    contractId: 'C002',
    roleCode: 'R02',
    skillCode: 'S02',
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
    permissions: ['CLAIM_VIEW', 'PATIENT_VIEW'],
    status: 'ACTIVE',
    invitedAt: new Date(),
    acceptedAt: new Date(),
    revokedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  delegateRelStore[P2_DELEGATE_REL_ID] = {
    relationshipId: P2_DELEGATE_REL_ID,
    physicianId: P2_PROVIDER_ID,
    delegateUserId: 'some-other-delegate-user-id',
    permissions: ['CLAIM_VIEW'],
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
  prefsStore[P2_PROVIDER_ID] = {
    preferenceId: 'pref-p2',
    providerId: P2_PROVIDER_ID,
    ahcipSubmissionMode: 'AUTO_ALL',
    wcbSubmissionMode: 'AUTO_CLEAN',
    batchReviewReminder: false,
    deadlineReminderDays: 14,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- H-Link Configurations ---
  hlinkStore[P1_PROVIDER_ID] = {
    hlinkConfigId: 'hlink-p1',
    providerId: P1_PROVIDER_ID,
    submitterPrefix: 'MER1',
    accreditationStatus: 'ACTIVE',
    credentialSecretRef: 'secret-ref-p1',
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  hlinkStore[P2_PROVIDER_ID] = {
    hlinkConfigId: 'hlink-p2',
    providerId: P2_PROVIDER_ID,
    submitterPrefix: 'MER2',
    accreditationStatus: 'PENDING',
    credentialSecretRef: 'secret-ref-p2',
    createdAt: new Date(),
    updatedAt: new Date(),
  };
}

// ---------------------------------------------------------------------------
// Physician-scoped mock provider repository
// ---------------------------------------------------------------------------

function createScopedProviderRepo() {
  return {
    // Profile
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

    // BAs — scoped to providerId
    listBas: vi.fn(async (providerId: string) => {
      return Object.values(basStore).filter((ba: any) => ba.providerId === providerId);
    }),
    listBasForProvider: vi.fn(async (providerId: string) => {
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

    // Locations — scoped to providerId
    listLocations: vi.fn(async (providerId: string) => {
      return Object.values(locationsStore).filter((loc: any) => loc.providerId === providerId);
    }),
    listLocationsForProvider: vi.fn(async (providerId: string) => {
      return Object.values(locationsStore).filter((loc: any) => loc.providerId === providerId);
    }),
    listActiveLocationsForProvider: vi.fn(async (providerId: string) => {
      return Object.values(locationsStore).filter((loc: any) => loc.providerId === providerId && loc.isActive);
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

    // WCB Configs — scoped to providerId
    listWcbConfigs: vi.fn(async (providerId: string) => {
      return Object.values(wcbStore).filter((wcb: any) => wcb.providerId === providerId);
    }),
    listWcbConfigsForProvider: vi.fn(async (providerId: string) => {
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
      configs.forEach((wcb: any) => {
        (wcb.permittedFormTypes ?? []).forEach((f: string) => allForms.add(f));
      });
      return Array.from(allForms);
    }),
    getAggregatedFormPermissions: vi.fn(async (providerId: string) => {
      const configs = Object.values(wcbStore).filter((wcb: any) => wcb.providerId === providerId);
      const allForms = new Set<string>();
      configs.forEach((wcb: any) => {
        (wcb.permittedFormTypes ?? []).forEach((f: string) => allForms.add(f));
      });
      return Array.from(allForms);
    }),
    getWcbConfigForForm: vi.fn(async (providerId: string, formId: string) => {
      const config = Object.values(wcbStore).find(
        (wcb: any) => wcb.providerId === providerId && (wcb.permittedFormTypes ?? []).includes(formId),
      );
      if (!config) return null;
      return { wcbConfigId: (config as any).wcbConfigId, contractId: (config as any).contractId, roleCode: (config as any).roleCode };
    }),

    // Submission Preferences — scoped to providerId
    findSubmissionPreferences: vi.fn(async (providerId: string) => {
      return prefsStore[providerId] ?? undefined;
    }),
    upsertSubmissionPreferences: vi.fn(async (providerId: string, data: any) => {
      const existing = prefsStore[providerId] ?? {};
      prefsStore[providerId] = { ...existing, ...data, providerId, updatedAt: new Date() };
      return prefsStore[providerId];
    }),

    // H-Link Config — scoped to providerId
    findHlinkConfig: vi.fn(async (providerId: string) => {
      return hlinkStore[providerId] ?? undefined;
    }),
    upsertHlinkConfig: vi.fn(async (providerId: string, data: any) => {
      const existing = hlinkStore[providerId] ?? {};
      hlinkStore[providerId] = { ...existing, ...data, providerId, updatedAt: new Date() };
      return hlinkStore[providerId];
    }),

    // Delegates — scoped to physicianId
    listDelegates: vi.fn(async (physicianId: string) => {
      return Object.values(delegateRelStore).filter(
        (rel: any) => rel.physicianId === physicianId,
      );
    }),
    listDelegatesForPhysician: vi.fn(async (physicianId: string) => {
      return Object.values(delegateRelStore).filter(
        (rel: any) => rel.physicianId === physicianId,
      );
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

    // Delegate self-service
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

    // Onboarding
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

    // Internal API helpers
    getProviderContext: vi.fn(async () => undefined),
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
        error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.validation },
      });
    }
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    });
  });

  await testApp.register(providerRoutes, { deps: handlerDeps });
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

function asDelegate(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
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

describe('Provider Physician Tenant Isolation — MOST CRITICAL (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsersAndSessions();
    seedTestData();
  });

  // =========================================================================
  // 1. Provider Profile Isolation
  // =========================================================================

  describe('Provider profile isolation', () => {
    it('GET /api/v1/providers/me as physician1 returns physician1 data', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.providerId).toBe(P1_PROVIDER_ID);
      expect(body.data.firstName).toBe('Alice');
      expect(body.data.billingNumber).toBe('111111');
    });

    it('GET /api/v1/providers/me as physician2 returns physician2 data', async () => {
      const res = await asPhysician2('GET', '/api/v1/providers/me');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.providerId).toBe(P2_PROVIDER_ID);
      expect(body.data.firstName).toBe('Bob');
      expect(body.data.billingNumber).toBe('222222');
    });

    it('physician1 profile never contains physician2 data', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('222222'); // P2's billing number
      expect(rawBody).not.toContain('CPSA-002'); // P2's CPSA number
      expect(rawBody).not.toContain('"Bob"');
    });
  });

  // =========================================================================
  // 2. Business Arrangement Isolation
  // =========================================================================

  describe('Business arrangement isolation', () => {
    it('physician1 only sees own BAs via GET /api/v1/providers/me/bas', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/bas');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      body.data.forEach((ba: any) => {
        expect(ba.providerId).toBe(P1_PROVIDER_ID);
      });
      // Should not contain P2's BA
      expect(res.body).not.toContain(P2_BA_ID);
    });

    it('physician2 only sees own BAs via GET /api/v1/providers/me/bas', async () => {
      const res = await asPhysician2('GET', '/api/v1/providers/me/bas');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      body.data.forEach((ba: any) => {
        expect(ba.providerId).toBe(P2_PROVIDER_ID);
      });
      expect(res.body).not.toContain(P1_BA_ID);
    });

    it('physician1 cannot update physician2 BA via PUT /api/v1/providers/me/bas/:id — returns 404', async () => {
      const res = await asPhysician1('PUT', `/api/v1/providers/me/bas/${P2_BA_ID}`, {
        status: 'INACTIVE',
      });
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      // Must not reveal any info about P2's BA
      expect(body.data).toBeUndefined();
      expect(res.body).not.toContain(P2_BA_ID);
      expect(res.body).not.toContain(P2_PROVIDER_ID);
    });

    it('physician1 cannot deactivate physician2 BA via DELETE /api/v1/providers/me/bas/:id — returns 404', async () => {
      const res = await asPhysician1('DELETE', `/api/v1/providers/me/bas/${P2_BA_ID}`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
    });

    it('physician2 cannot update physician1 BA — returns 404', async () => {
      const res = await asPhysician2('PUT', `/api/v1/providers/me/bas/${P1_BA_ID}`, {
        status: 'INACTIVE',
      });
      expect(res.statusCode).toBe(404);
    });

    it('physician2 cannot deactivate physician1 BA — returns 404', async () => {
      const res = await asPhysician2('DELETE', `/api/v1/providers/me/bas/${P1_BA_ID}`);
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 3. Practice Location Isolation
  // =========================================================================

  describe('Practice location isolation', () => {
    it('physician1 only sees own locations via GET /api/v1/providers/me/locations', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/locations');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      body.data.forEach((loc: any) => {
        expect(loc.providerId).toBe(P1_PROVIDER_ID);
      });
      expect(res.body).not.toContain(P2_LOCATION_ID);
      expect(res.body).not.toContain('Bob Clinic');
    });

    it('physician2 only sees own locations', async () => {
      const res = await asPhysician2('GET', '/api/v1/providers/me/locations');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((loc: any) => {
        expect(loc.providerId).toBe(P2_PROVIDER_ID);
      });
      expect(res.body).not.toContain(P1_LOCATION_ID);
      expect(res.body).not.toContain('Alice Clinic');
    });

    it('physician1 cannot modify physician2 location via PUT — returns 404', async () => {
      const res = await asPhysician1('PUT', `/api/v1/providers/me/locations/${P2_LOCATION_ID}`, {
        name: 'Hijacked Clinic',
      });
      expect(res.statusCode).toBe(404);
      expect(res.body).not.toContain(P2_LOCATION_ID);
      expect(res.body).not.toContain(P2_PROVIDER_ID);
    });

    it('physician1 cannot set physician2 location as default — returns 404', async () => {
      const res = await asPhysician1('PUT', `/api/v1/providers/me/locations/${P2_LOCATION_ID}/set-default`);
      expect(res.statusCode).toBe(404);
      expect(res.body).not.toContain(P2_LOCATION_ID);
    });

    it('physician1 cannot deactivate physician2 location via DELETE — returns 404', async () => {
      const res = await asPhysician1('DELETE', `/api/v1/providers/me/locations/${P2_LOCATION_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.body).not.toContain(P2_LOCATION_ID);
    });

    it('physician2 cannot modify physician1 location — returns 404', async () => {
      const res = await asPhysician2('PUT', `/api/v1/providers/me/locations/${P1_LOCATION_ID}`, {
        name: 'Attacker Clinic',
      });
      expect(res.statusCode).toBe(404);
    });

    it('physician2 cannot set physician1 location as default — returns 404', async () => {
      const res = await asPhysician2('PUT', `/api/v1/providers/me/locations/${P1_LOCATION_ID}/set-default`);
      expect(res.statusCode).toBe(404);
    });

    it('physician2 cannot deactivate physician1 location — returns 404', async () => {
      const res = await asPhysician2('DELETE', `/api/v1/providers/me/locations/${P1_LOCATION_ID}`);
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 4. WCB Configuration Isolation
  // =========================================================================

  describe('WCB configuration isolation', () => {
    it('physician1 only sees own WCB configs via GET /api/v1/providers/me/wcb', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/wcb');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      body.data.forEach((wcb: any) => {
        expect(wcb.providerId).toBe(P1_PROVIDER_ID);
      });
      expect(res.body).not.toContain(P2_WCB_ID);
    });

    it('physician2 only sees own WCB configs', async () => {
      const res = await asPhysician2('GET', '/api/v1/providers/me/wcb');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((wcb: any) => {
        expect(wcb.providerId).toBe(P2_PROVIDER_ID);
      });
      expect(res.body).not.toContain(P1_WCB_ID);
    });

    it('physician1 cannot update physician2 WCB config via PUT — returns 404', async () => {
      const res = await asPhysician1('PUT', `/api/v1/providers/me/wcb/${P2_WCB_ID}`, {
        skill_code: 'HIJACKED',
      });
      expect(res.statusCode).toBe(404);
      expect(res.body).not.toContain(P2_WCB_ID);
      expect(res.body).not.toContain(P2_PROVIDER_ID);
    });

    it('physician1 cannot delete physician2 WCB config via DELETE — returns 404', async () => {
      const res = await asPhysician1('DELETE', `/api/v1/providers/me/wcb/${P2_WCB_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.body).not.toContain(P2_WCB_ID);
    });

    it('physician2 cannot update physician1 WCB config — returns 404', async () => {
      const res = await asPhysician2('PUT', `/api/v1/providers/me/wcb/${P1_WCB_ID}`, {
        skill_code: 'ATTACKER',
      });
      expect(res.statusCode).toBe(404);
    });

    it('physician2 cannot delete physician1 WCB config — returns 404', async () => {
      const res = await asPhysician2('DELETE', `/api/v1/providers/me/wcb/${P1_WCB_ID}`);
      expect(res.statusCode).toBe(404);
    });

    it('physician1 WCB form permissions do not include physician2 forms', async () => {
      const res1 = await asPhysician1('GET', '/api/v1/providers/me/wcb/form-permissions');
      const res2 = await asPhysician2('GET', '/api/v1/providers/me/wcb/form-permissions');
      expect(res1.statusCode).toBe(200);
      expect(res2.statusCode).toBe(200);
      // Each should only see their own form permissions
      // (Both happen to have WCB_PHYSICIAN_FIRST_REPORT but scoped independently)
      expect(res1.body).not.toContain(P2_WCB_ID);
      expect(res2.body).not.toContain(P1_WCB_ID);
    });
  });

  // =========================================================================
  // 5. Delegate Relationship Isolation
  // =========================================================================

  describe('Delegate relationship isolation', () => {
    it('physician1 only sees own delegates via GET /api/v1/providers/me/delegates', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/delegates');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      body.data.forEach((rel: any) => {
        expect(rel.physicianId).toBe(P1_PROVIDER_ID);
      });
      expect(res.body).not.toContain(P2_DELEGATE_REL_ID);
    });

    it('physician2 only sees own delegates', async () => {
      const res = await asPhysician2('GET', '/api/v1/providers/me/delegates');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((rel: any) => {
        expect(rel.physicianId).toBe(P2_PROVIDER_ID);
      });
      expect(res.body).not.toContain(P1_DELEGATE_REL_ID);
    });

    it('physician1 cannot revoke physician2 delegate via POST /revoke — returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/providers/me/delegates/${P2_DELEGATE_REL_ID}/revoke`);
      expect(res.statusCode).toBe(404);
      expect(res.body).not.toContain(P2_DELEGATE_REL_ID);
      expect(res.body).not.toContain(P2_PROVIDER_ID);
    });

    it('physician1 cannot modify physician2 delegate permissions — returns 404', async () => {
      const res = await asPhysician1('PUT', `/api/v1/providers/me/delegates/${P2_DELEGATE_REL_ID}/permissions`, {
        permissions: ['CLAIM_VIEW', 'CLAIM_CREATE'],
      });
      expect(res.statusCode).toBe(404);
      expect(res.body).not.toContain(P2_DELEGATE_REL_ID);
    });

    it('physician2 cannot revoke physician1 delegate — returns 404', async () => {
      const res = await asPhysician2('POST', `/api/v1/providers/me/delegates/${P1_DELEGATE_REL_ID}/revoke`);
      expect(res.statusCode).toBe(404);
    });

    it('physician2 cannot modify physician1 delegate permissions — returns 404', async () => {
      const res = await asPhysician2('PUT', `/api/v1/providers/me/delegates/${P1_DELEGATE_REL_ID}/permissions`, {
        permissions: ['CLAIM_VIEW'],
      });
      expect(res.statusCode).toBe(404);
    });
  });

  // =========================================================================
  // 6. Delegate Cross-Context Isolation
  // =========================================================================

  describe('Delegate cross-context isolation', () => {
    it('delegate linked to physician1 cannot switch to physician2 context — returns 404', async () => {
      const res = await asDelegate('POST', `/api/v1/delegates/me/switch-context/${P2_PROVIDER_ID}`);
      // Should fail because delegate has no active relationship with physician2
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();
      // Must not reveal physician2's data
      expect(res.body).not.toContain(P2_PROVIDER_ID);
    });

    it('delegate can list physicians and sees only physician1', async () => {
      const res = await asDelegate('GET', '/api/v1/delegates/me/physicians');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBe(1);
      expect(body.data[0].physicianId).toBe(P1_PROVIDER_ID);
      // Must not contain physician2 data
      expect(res.body).not.toContain(P2_PROVIDER_ID);
      expect(res.body).not.toContain('Bob');
    });

    it('delegate viewing physician1 context sees physician1 data only', async () => {
      // Delegate's delegateContext is set to physician1 — so /me/bas returns physician1 BAs
      const res = await asDelegate('GET', '/api/v1/providers/me/bas');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((ba: any) => {
        expect(ba.providerId).toBe(P1_PROVIDER_ID);
      });
      expect(res.body).not.toContain(P2_BA_ID);
      expect(res.body).not.toContain(P2_PROVIDER_ID);
    });

    it('delegate viewing physician1 locations sees physician1 data only', async () => {
      const res = await asDelegate('GET', '/api/v1/providers/me/locations');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      body.data.forEach((loc: any) => {
        expect(loc.providerId).toBe(P1_PROVIDER_ID);
      });
      expect(res.body).not.toContain(P2_LOCATION_ID);
    });
  });

  // =========================================================================
  // 7. Submission Preferences Isolation
  // =========================================================================

  describe('Submission preferences isolation', () => {
    it('physician1 sees own submission preferences', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/submission-preferences');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.ahcipSubmissionMode).toBe('AUTO_CLEAN');
      // Must not contain P2's preferences
      expect(res.body).not.toContain('AUTO_ALL'); // P2's ahcip mode
    });

    it('physician2 sees own submission preferences', async () => {
      const res = await asPhysician2('GET', '/api/v1/providers/me/submission-preferences');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.ahcipSubmissionMode).toBe('AUTO_ALL');
    });

    it('physician1 cannot see physician2 submission preferences', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/submission-preferences');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      // P2 has deadlineReminderDays=14, P1 has 7
      const body = JSON.parse(rawBody);
      expect(body.data.deadlineReminderDays).toBe(7);
    });
  });

  // =========================================================================
  // 8. H-Link Configuration Isolation
  // =========================================================================

  describe('H-Link configuration isolation', () => {
    it('physician1 sees own H-Link config', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/hlink');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.submitterPrefix).toBe('MER1');
      expect(body.data.accreditationStatus).toBe('ACTIVE');
    });

    it('physician2 sees own H-Link config', async () => {
      const res = await asPhysician2('GET', '/api/v1/providers/me/hlink');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.submitterPrefix).toBe('MER2');
      expect(body.data.accreditationStatus).toBe('PENDING');
    });

    it('physician1 H-Link response does not contain physician2 data', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/hlink');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('MER2');
      expect(rawBody).not.toContain('secret-ref-p2');
    });

    it('H-Link config never exposes credential secret ref', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/hlink');
      expect(res.statusCode).toBe(200);
      const rawBody = res.body;
      expect(rawBody).not.toContain('secret-ref-p1');
      expect(rawBody).not.toContain('credentialSecretRef');
    });
  });

  // =========================================================================
  // 9. Cross-user access attempts always return 404 (not 403)
  // =========================================================================

  describe('Cross-user access returns 404 (not 403) to prevent resource enumeration', () => {
    it('accessing another physician BA returns 404 not 403', async () => {
      const res = await asPhysician1('PUT', `/api/v1/providers/me/bas/${P2_BA_ID}`, { status: 'INACTIVE' });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('accessing another physician location returns 404 not 403', async () => {
      const res = await asPhysician1('PUT', `/api/v1/providers/me/locations/${P2_LOCATION_ID}`, { name: 'X' });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('accessing another physician WCB config returns 404 not 403', async () => {
      const res = await asPhysician1('PUT', `/api/v1/providers/me/wcb/${P2_WCB_ID}`, { skill_code: 'X' });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('accessing another physician delegate relationship returns 404 not 403', async () => {
      const res = await asPhysician1('POST', `/api/v1/providers/me/delegates/${P2_DELEGATE_REL_ID}/revoke`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('delegate switching to unauthorized physician context returns 404 not 403', async () => {
      const res = await asDelegate('POST', `/api/v1/delegates/me/switch-context/${P2_PROVIDER_ID}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 10. 404 responses do not confirm resource existence
  // =========================================================================

  describe('404 responses reveal no information about the target resource', () => {
    it('404 for cross-tenant BA does not contain the BA ID', async () => {
      const res = await asPhysician1('PUT', `/api/v1/providers/me/bas/${P2_BA_ID}`, { status: 'INACTIVE' });
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_BA_ID);
      expect(rawBody).not.toContain(P2_PROVIDER_ID);
      expect(rawBody).not.toContain('22222'); // P2's BA number
    });

    it('404 for cross-tenant location does not contain location details', async () => {
      const res = await asPhysician1('PUT', `/api/v1/providers/me/locations/${P2_LOCATION_ID}`, { name: 'X' });
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_LOCATION_ID);
      expect(rawBody).not.toContain('Bob Clinic');
      expect(rawBody).not.toContain('Calgary');
    });

    it('404 for cross-tenant WCB does not contain WCB details', async () => {
      const res = await asPhysician1('DELETE', `/api/v1/providers/me/wcb/${P2_WCB_ID}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_WCB_ID);
      expect(rawBody).not.toContain('C002'); // P2's contract ID
    });

    it('404 for cross-tenant delegate does not contain delegate details', async () => {
      const res = await asPhysician1('PUT', `/api/v1/providers/me/delegates/${P2_DELEGATE_REL_ID}/permissions`, {
        permissions: ['CLAIM_VIEW'],
      });
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain(P2_DELEGATE_REL_ID);
      expect(rawBody).not.toContain('some-other-delegate-user-id');
    });
  });

  // =========================================================================
  // 11. Bidirectional isolation — verify BOTH directions
  // =========================================================================

  describe('Bidirectional isolation (both physicians tested)', () => {
    it('physician1 BA list contains P1_BA_ID and not P2_BA_ID', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/bas');
      const body = JSON.parse(res.body);
      const ids = body.data.map((ba: any) => ba.baId);
      expect(ids).toContain(P1_BA_ID);
      expect(ids).not.toContain(P2_BA_ID);
    });

    it('physician2 BA list contains P2_BA_ID and not P1_BA_ID', async () => {
      const res = await asPhysician2('GET', '/api/v1/providers/me/bas');
      const body = JSON.parse(res.body);
      const ids = body.data.map((ba: any) => ba.baId);
      expect(ids).toContain(P2_BA_ID);
      expect(ids).not.toContain(P1_BA_ID);
    });

    it('physician1 location list contains P1_LOCATION_ID and not P2_LOCATION_ID', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/locations');
      const body = JSON.parse(res.body);
      const ids = body.data.map((loc: any) => loc.locationId);
      expect(ids).toContain(P1_LOCATION_ID);
      expect(ids).not.toContain(P2_LOCATION_ID);
    });

    it('physician2 location list contains P2_LOCATION_ID and not P1_LOCATION_ID', async () => {
      const res = await asPhysician2('GET', '/api/v1/providers/me/locations');
      const body = JSON.parse(res.body);
      const ids = body.data.map((loc: any) => loc.locationId);
      expect(ids).toContain(P2_LOCATION_ID);
      expect(ids).not.toContain(P1_LOCATION_ID);
    });

    it('physician1 WCB list contains P1_WCB_ID and not P2_WCB_ID', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/wcb');
      const body = JSON.parse(res.body);
      const ids = body.data.map((wcb: any) => wcb.wcbConfigId);
      expect(ids).toContain(P1_WCB_ID);
      expect(ids).not.toContain(P2_WCB_ID);
    });

    it('physician2 WCB list contains P2_WCB_ID and not P1_WCB_ID', async () => {
      const res = await asPhysician2('GET', '/api/v1/providers/me/wcb');
      const body = JSON.parse(res.body);
      const ids = body.data.map((wcb: any) => wcb.wcbConfigId);
      expect(ids).toContain(P2_WCB_ID);
      expect(ids).not.toContain(P1_WCB_ID);
    });

    it('physician1 delegate list contains P1_DELEGATE_REL_ID and not P2_DELEGATE_REL_ID', async () => {
      const res = await asPhysician1('GET', '/api/v1/providers/me/delegates');
      const body = JSON.parse(res.body);
      const ids = body.data.map((rel: any) => rel.relationshipId);
      expect(ids).toContain(P1_DELEGATE_REL_ID);
      expect(ids).not.toContain(P2_DELEGATE_REL_ID);
    });

    it('physician2 delegate list contains P2_DELEGATE_REL_ID and not P1_DELEGATE_REL_ID', async () => {
      const res = await asPhysician2('GET', '/api/v1/providers/me/delegates');
      const body = JSON.parse(res.body);
      const ids = body.data.map((rel: any) => rel.relationshipId);
      expect(ids).toContain(P2_DELEGATE_REL_ID);
      expect(ids).not.toContain(P1_DELEGATE_REL_ID);
    });
  });

  // =========================================================================
  // 12. Non-existent resource IDs still return 404 (not 500)
  // =========================================================================

  describe('Non-existent resource IDs return 404', () => {
    const NONEXISTENT_UUID = '99999999-9999-9999-9999-999999999999';

    it('GET by non-existent BA ID returns 404', async () => {
      const res = await asPhysician1('PUT', `/api/v1/providers/me/bas/${NONEXISTENT_UUID}`, { status: 'INACTIVE' });
      expect(res.statusCode).toBe(404);
    });

    it('GET by non-existent location ID returns 404', async () => {
      const res = await asPhysician1('PUT', `/api/v1/providers/me/locations/${NONEXISTENT_UUID}`, { name: 'X' });
      expect(res.statusCode).toBe(404);
    });

    it('DELETE by non-existent WCB config ID returns 404', async () => {
      const res = await asPhysician1('DELETE', `/api/v1/providers/me/wcb/${NONEXISTENT_UUID}`);
      expect(res.statusCode).toBe(404);
    });

    it('POST revoke by non-existent delegate rel ID returns 404', async () => {
      const res = await asPhysician1('POST', `/api/v1/providers/me/delegates/${NONEXISTENT_UUID}/revoke`);
      expect(res.statusCode).toBe(404);
    });
  });
});
