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
import { randomBytes, createHash } from 'node:crypto';
import { ProviderAuditAction } from '@meritum/shared/constants/provider.constants.js';

// ---------------------------------------------------------------------------
// Fixed test identities
// ---------------------------------------------------------------------------

const PHYSICIAN_SESSION_TOKEN = randomBytes(32).toString('hex');
const PHYSICIAN_SESSION_TOKEN_HASH = hashToken(PHYSICIAN_SESSION_TOKEN);
const PHYSICIAN_USER_ID = '11111111-0000-0000-0000-000000000001';
const PHYSICIAN_PROVIDER_ID = PHYSICIAN_USER_ID; // 1:1 mapping
const PHYSICIAN_SESSION_ID = '11111111-0000-0000-0000-000000000011';

// Resource IDs (deterministic)
const BA_ID = 'aaaaaaaa-0000-0000-0000-000000000001';
const LOCATION_ID = 'bbbbbbbb-0000-0000-0000-000000000001';
const LOCATION_ID_2 = 'bbbbbbbb-0000-0000-0000-000000000002';
const WCB_ID = 'cccccccc-0000-0000-0000-000000000001';
const DELEGATE_REL_ID = 'dddddddd-0000-0000-0000-000000000001';
const PREF_ID = 'eeeeeeee-0000-0000-0000-000000000001';
const HLINK_CONFIG_ID = 'ffffffff-0000-0000-0000-000000000001';

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
let auditEntries: Array<Record<string, unknown>> = [];

// ---------------------------------------------------------------------------
// Mock data stores
// ---------------------------------------------------------------------------

let providerProfiles: Record<string, any> = {};
let basStore: Record<string, any> = {};
let locationsStore: Record<string, any> = {};
let wcbStore: Record<string, any> = {};
let delegateRelStore: Record<string, any> = {};
let prefsStore: Record<string, any> = {};
let hlinkStore: Record<string, any> = {};
let tokenStoreData: Record<string, { tokenHash: string; expiresAt: Date }> = {};

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
    appendAuditLog: vi.fn(async (entry: Record<string, unknown>) => {
      auditEntries.push(entry);
    }),
  };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

function seedTestData() {
  providerProfiles = {};
  basStore = {};
  locationsStore = {};
  wcbStore = {};
  delegateRelStore = {};
  prefsStore = {};
  hlinkStore = {};
  tokenStoreData = {};

  providerProfiles[PHYSICIAN_PROVIDER_ID] = {
    providerId: PHYSICIAN_PROVIDER_ID,
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

  basStore[BA_ID] = {
    baId: BA_ID,
    providerId: PHYSICIAN_PROVIDER_ID,
    baNumber: '11111',
    baType: 'FFS',
    isPrimary: true,
    status: 'ACTIVE',
    effectiveDate: '2025-01-01',
    endDate: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  locationsStore[LOCATION_ID] = {
    locationId: LOCATION_ID,
    providerId: PHYSICIAN_PROVIDER_ID,
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

  locationsStore[LOCATION_ID_2] = {
    locationId: LOCATION_ID_2,
    providerId: PHYSICIAN_PROVIDER_ID,
    name: 'Second Clinic',
    functionalCentre: 'FC02',
    facilityNumber: null,
    addressLine1: '456 Other St',
    addressLine2: null,
    city: 'Calgary',
    province: 'AB',
    postalCode: 'T2A0B2',
    communityCode: null,
    isActive: true,
    isDefault: false,
    rrnpEligible: false,
    rrnpPercentage: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  wcbStore[WCB_ID] = {
    wcbConfigId: WCB_ID,
    providerId: PHYSICIAN_PROVIDER_ID,
    contractId: 'C001',
    roleCode: 'R01',
    skillCode: 'S01',
    isDefault: true,
    permittedFormTypes: ['WCB_PHYSICIAN_FIRST_REPORT'],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  delegateRelStore[DELEGATE_REL_ID] = {
    relationshipId: DELEGATE_REL_ID,
    physicianId: PHYSICIAN_PROVIDER_ID,
    delegateUserId: '99999999-0000-0000-0000-000000000099',
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

  prefsStore[PHYSICIAN_PROVIDER_ID] = {
    preferenceId: PREF_ID,
    providerId: PHYSICIAN_PROVIDER_ID,
    ahcipSubmissionMode: 'AUTO_CLEAN',
    wcbSubmissionMode: 'REQUIRE_APPROVAL',
    batchReviewReminder: true,
    deadlineReminderDays: 7,
    updatedBy: PHYSICIAN_USER_ID,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  hlinkStore[PHYSICIAN_PROVIDER_ID] = {
    hlinkConfigId: HLINK_CONFIG_ID,
    providerId: PHYSICIAN_PROVIDER_ID,
    submitterPrefix: 'MER1',
    accreditationStatus: 'ACTIVE',
    accreditationDate: '2025-01-15',
    lastSuccessfulTransmission: new Date('2026-02-01'),
    credentialSecretRef: 'vault://secrets/hlink/credential-do-not-leak',
    createdAt: new Date(),
    updatedAt: new Date(),
  };
}

function seedUsersAndSessions() {
  users.length = 0;
  sessions.length = 0;

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
}

// ---------------------------------------------------------------------------
// Scoped provider repository mock
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
        hlinkConfig: hlinkStore[providerId]
          ? { ...hlinkStore[providerId], credentialSecretRef: undefined }
          : null,
      };
    }),
    createProvider: vi.fn(async () => ({})),
    updateProvider: vi.fn(async (providerId: string, data: any) => {
      const existing = providerProfiles[providerId];
      if (!existing) return undefined;
      const updated = { ...existing, ...data, updatedAt: new Date() };
      providerProfiles[providerId] = updated;
      return updated;
    }),
    // BA methods
    listBas: vi.fn(async (providerId: string) => {
      return Object.values(basStore).filter((ba: any) => ba.providerId === providerId);
    }),
    listBasForProvider: vi.fn(async (providerId: string) => {
      return Object.values(basStore).filter((ba: any) => ba.providerId === providerId);
    }),
    listActiveBasForProvider: vi.fn(async (providerId: string) => {
      return Object.values(basStore).filter(
        (ba: any) => ba.providerId === providerId && ba.status !== 'INACTIVE',
      );
    }),
    countActiveBasForProvider: vi.fn(async (providerId: string) => {
      return Object.values(basStore).filter(
        (ba: any) => ba.providerId === providerId && ba.status !== 'INACTIVE',
      ).length;
    }),
    findBaByNumber: vi.fn(async (baNumber: string) => {
      return Object.values(basStore).find(
        (ba: any) => ba.baNumber === baNumber && ba.status !== 'INACTIVE',
      ) ?? undefined;
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
      const updated = { ...ba, ...data, updatedAt: new Date() };
      basStore[baId] = updated;
      return updated;
    }),
    deactivateBa: vi.fn(async (baId: string, providerId: string) => {
      const ba = basStore[baId];
      if (!ba || ba.providerId !== providerId) return undefined;
      const deactivated = { ...ba, status: 'INACTIVE', updatedAt: new Date() };
      basStore[baId] = deactivated;
      return deactivated;
    }),
    findPcpcmEnrolmentForProvider: vi.fn(async () => undefined),
    createPcpcmEnrolment: vi.fn(async () => ({})),
    updatePcpcmEnrolment: vi.fn(async () => ({})),
    // Location methods
    listLocations: vi.fn(async (providerId: string) => {
      return Object.values(locationsStore).filter((loc: any) => loc.providerId === providerId);
    }),
    listLocationsForProvider: vi.fn(async (providerId: string) => {
      return Object.values(locationsStore).filter((loc: any) => loc.providerId === providerId);
    }),
    listActiveLocationsForProvider: vi.fn(async (providerId: string) => {
      return Object.values(locationsStore).filter(
        (loc: any) => loc.providerId === providerId && loc.isActive,
      );
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
      const updated = { ...loc, ...data, updatedAt: new Date() };
      locationsStore[locationId] = updated;
      return updated;
    }),
    getDefaultLocation: vi.fn(async (providerId: string) => {
      return Object.values(locationsStore).find(
        (loc: any) => loc.providerId === providerId && loc.isDefault && loc.isActive,
      ) ?? null;
    }),
    setDefaultLocation: vi.fn(async (locationId: string, providerId: string) => {
      const loc = locationsStore[locationId];
      if (!loc || loc.providerId !== providerId) return undefined;
      // Unset other defaults
      for (const l of Object.values(locationsStore)) {
        if ((l as any).providerId === providerId) (l as any).isDefault = false;
      }
      locationsStore[locationId] = { ...loc, isDefault: true, updatedAt: new Date() };
      return locationsStore[locationId];
    }),
    deactivateLocation: vi.fn(async (locationId: string, providerId: string) => {
      const loc = locationsStore[locationId];
      if (!loc || loc.providerId !== providerId) return undefined;
      const deactivated = { ...loc, isActive: false, isDefault: false, updatedAt: new Date() };
      locationsStore[locationId] = deactivated;
      return deactivated;
    }),
    // WCB methods
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
      const updated = { ...wcb, ...data, updatedAt: new Date() };
      wcbStore[wcbConfigId] = updated;
      return updated;
    }),
    deleteWcbConfig: vi.fn(async (wcbConfigId: string, providerId: string) => {
      const wcb = wcbStore[wcbConfigId];
      if (!wcb || wcb.providerId !== providerId) return false;
      delete wcbStore[wcbConfigId];
      return true;
    }),
    removeWcbConfig: vi.fn(async (wcbConfigId: string, providerId: string) => {
      const wcb = wcbStore[wcbConfigId];
      if (!wcb || wcb.providerId !== providerId) return undefined;
      delete wcbStore[wcbConfigId];
      return wcb;
    }),
    getFormPermissions: vi.fn(async (providerId: string) => {
      const configs = Object.values(wcbStore).filter((wcb: any) => wcb.providerId === providerId);
      const allForms = new Set<string>();
      configs.forEach((wcb: any) => { (wcb.permittedFormTypes ?? []).forEach((f: string) => allForms.add(f)); });
      return Array.from(allForms);
    }),
    getAggregatedFormPermissions: vi.fn(async (providerId: string) => {
      const configs = Object.values(wcbStore).filter((wcb: any) => wcb.providerId === providerId);
      const allForms = new Set<string>();
      configs.forEach((wcb: any) => { (wcb.permittedFormTypes ?? []).forEach((f: string) => allForms.add(f)); });
      return Array.from(allForms);
    }),
    // Submission Preferences
    findSubmissionPreferences: vi.fn(async (providerId: string) => {
      return prefsStore[providerId] ?? undefined;
    }),
    createSubmissionPreferences: vi.fn(async (data: any) => {
      prefsStore[data.providerId] = { preferenceId: PREF_ID, ...data, createdAt: new Date(), updatedAt: new Date() };
      return prefsStore[data.providerId];
    }),
    updateSubmissionPreferences: vi.fn(async (providerId: string, data: any, _actorId?: string) => {
      const existing = prefsStore[providerId];
      if (!existing) return undefined;
      prefsStore[providerId] = { ...existing, ...data, updatedAt: new Date() };
      return prefsStore[providerId];
    }),
    upsertSubmissionPreferences: vi.fn(async (providerId: string, data: any) => {
      const existing = prefsStore[providerId] ?? { preferenceId: PREF_ID };
      prefsStore[providerId] = { ...existing, ...data, providerId, updatedAt: new Date() };
      return prefsStore[providerId];
    }),
    // H-Link Config
    findHlinkConfig: vi.fn(async (providerId: string) => {
      return hlinkStore[providerId] ?? undefined;
    }),
    createHlinkConfig: vi.fn(async (data: any) => {
      hlinkStore[data.providerId] = { hlinkConfigId: HLINK_CONFIG_ID, ...data, createdAt: new Date(), updatedAt: new Date() };
      return hlinkStore[data.providerId];
    }),
    upsertHlinkConfig: vi.fn(async (providerId: string, data: any) => {
      const existing = hlinkStore[providerId] ?? { hlinkConfigId: HLINK_CONFIG_ID };
      hlinkStore[providerId] = { ...existing, ...data, providerId, updatedAt: new Date() };
      return hlinkStore[providerId];
    }),
    updateHlinkConfig: vi.fn(async (providerId: string, data: any) => {
      const existing = hlinkStore[providerId];
      if (!existing) return undefined;
      hlinkStore[providerId] = { ...existing, ...data, updatedAt: new Date() };
      return hlinkStore[providerId];
    }),
    // Delegate methods
    listDelegates: vi.fn(async (physicianId: string) => {
      return Object.values(delegateRelStore).filter((rel: any) => rel.physicianId === physicianId);
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
    createDelegateRelationship: vi.fn(async (data: any) => {
      const rel = {
        relationshipId: randomBytes(16).toString('hex'),
        ...data,
        status: 'INVITED',
        delegateEmail: 'newdelegate@example.com',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      delegateRelStore[rel.relationshipId] = rel;
      return rel;
    }),
    updateDelegatePermissions: vi.fn(async (relationshipId: string, physicianId: string, permissions: string[]) => {
      const rel = delegateRelStore[relationshipId];
      if (!rel || rel.physicianId !== physicianId) return undefined;
      const updated = { ...rel, permissions, updatedAt: new Date() };
      delegateRelStore[relationshipId] = updated;
      return updated;
    }),
    updateDelegateRelationshipPermissions: vi.fn(async () => ({})),
    revokeRelationship: vi.fn(async (relationshipId: string, physicianId: string, _actorId: string) => {
      const rel = delegateRelStore[relationshipId];
      if (!rel || rel.physicianId !== physicianId) return undefined;
      const revoked = { ...rel, status: 'REVOKED', revokedAt: new Date(), updatedAt: new Date() };
      delegateRelStore[relationshipId] = revoked;
      return revoked;
    }),
    revokeDelegateRelationship: vi.fn(async () => ({})),
    acceptRelationship: vi.fn(async (relationshipId: string) => {
      const rel = delegateRelStore[relationshipId];
      if (!rel) return undefined;
      const accepted = { ...rel, status: 'ACTIVE', acceptedAt: new Date(), updatedAt: new Date() };
      delegateRelStore[relationshipId] = accepted;
      return accepted;
    }),
    listPhysiciansForDelegate: vi.fn(async () => []),
    findActiveRelationship: vi.fn(async () => undefined),
    findDelegateLinkage: vi.fn(async () => undefined),
    // Onboarding
    getOnboardingStatus: vi.fn(async (providerId: string) => {
      const profile = providerProfiles[providerId];
      if (!profile) return undefined;
      const populated: string[] = [];
      if (profile.billingNumber) populated.push('billingNumber');
      if (profile.cpsaRegistrationNumber) populated.push('cpsaRegistrationNumber');
      if (profile.specialtyCode) populated.push('specialtyCode');
      if (profile.physicianType) populated.push('physicianType');
      return { populated };
    }),
    completeOnboarding: vi.fn(async (providerId: string) => {
      const profile = providerProfiles[providerId];
      if (!profile) return undefined;
      const updated = { ...profile, onboardingCompleted: true, updatedAt: new Date() };
      providerProfiles[providerId] = updated;
      return updated;
    }),
    // Internal API helpers
    getProviderContext: vi.fn(async () => undefined),
    getBaForClaim: vi.fn(async () => undefined),
    findWcbConfigByContractRole: vi.fn(async () => undefined),
    findPcpcmEnrolment: vi.fn(async () => undefined),
    getWcbConfigForForm: vi.fn(async () => null),
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

// ---------------------------------------------------------------------------
// Token store mock
// ---------------------------------------------------------------------------

function createMockTokenStore() {
  return {
    storeTokenHash: vi.fn(async (relationshipId: string, tokenHash: string, expiresAt: Date) => {
      tokenStoreData[relationshipId] = { tokenHash, expiresAt };
    }),
    getTokenHash: vi.fn(async (relationshipId: string) => {
      return tokenStoreData[relationshipId] ?? null;
    }),
    deleteToken: vi.fn(async (relationshipId: string) => {
      delete tokenStoreData[relationshipId];
    }),
  };
}

// ---------------------------------------------------------------------------
// Shared service deps ref (accessible to tests for spy inspection)
// ---------------------------------------------------------------------------

let serviceDeps: ProviderServiceDeps;

function createStubServiceDeps(): ProviderServiceDeps {
  const deps: ProviderServiceDeps = {
    repo: createScopedProviderRepo() as any,
    auditRepo: createMockAuditRepo(),
    events: createMockEvents(),
    tokenStore: createMockTokenStore(),
    referenceData: {
      getRrnpRate: vi.fn(async () => null),
      getPcpcmBasket: vi.fn(async () => null),
      getWcbMatrixEntry: vi.fn(async (contractId: string, roleCode: string) => ({
        contractId,
        roleCode,
        permittedFormTypes: ['WCB_PHYSICIAN_FIRST_REPORT'],
      })),
    },
  };
  serviceDeps = deps;
  return deps;
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

  const deps = createStubServiceDeps();

  const handlerDeps: ProviderHandlerDeps = {
    serviceDeps: deps,
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
  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Request helper
// ---------------------------------------------------------------------------

function physicianRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${PHYSICIAN_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Audit entry finder
// ---------------------------------------------------------------------------

function findAuditEntry(action: string): Record<string, unknown> | undefined {
  return auditEntries.find((e) => e.action === action);
}

function findAuditEntries(action: string): Array<Record<string, unknown>> {
  return auditEntries.filter((e) => e.action === action);
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

beforeAll(async () => {
  app = await buildTestApp();
});

afterAll(async () => {
  await app.close();
});

beforeEach(() => {
  auditEntries.length = 0; // Clear in-place to preserve closure reference
  seedUsersAndSessions();
  seedTestData();
  // Reset all mock call counts for the audit repo
  vi.mocked(serviceDeps.auditRepo.appendAuditLog).mockClear();
});

// ===========================================================================
// AUDIT TRAIL — Provider Profile Events
// ===========================================================================

describe('Audit Trail — Provider Profile Events', () => {
  it('update profile produces provider.profile_updated audit entry with field-level diff', async () => {
    const res = await physicianRequest('PUT', '/api/v1/providers/me', {
      first_name: 'Updated',
      last_name: 'Name',
    });

    expect(res.statusCode).toBeLessThan(500);

    const entry = findAuditEntry(ProviderAuditAction.PROFILE_UPDATED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('provider.profile_updated');
    expect(entry!.category).toBe('provider');
    expect(entry!.resourceType).toBe('provider');
    expect(entry!.resourceId).toBe(PHYSICIAN_PROVIDER_ID);

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail).toBeDefined();
    expect(detail.changes).toBeDefined();
    // Should contain old/new for each changed field
    const changes = detail.changes as Record<string, { old: unknown; new: unknown }>;
    expect(changes.firstName).toBeDefined();
    expect(changes.firstName.old).toBe('Alice');
    expect(changes.firstName.new).toBe('Updated');
  });

  it('complete onboarding produces provider.onboarding_completed audit entry', async () => {
    // Set onboarding to not completed
    providerProfiles[PHYSICIAN_PROVIDER_ID].onboardingCompleted = false;

    const res = await physicianRequest('POST', '/api/v1/providers/me/complete-onboarding', {});

    expect(res.statusCode).toBeLessThan(500);

    const entry = findAuditEntry(ProviderAuditAction.ONBOARDING_COMPLETED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_PROVIDER_ID);
    expect(entry!.action).toBe('provider.onboarding_completed');
    expect(entry!.category).toBe('provider');
    expect(entry!.resourceType).toBe('provider');
    expect(entry!.resourceId).toBe(PHYSICIAN_PROVIDER_ID);

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail).toBeDefined();
    expect(detail.completedAt).toBeDefined();
    expect(typeof detail.completedAt).toBe('string');
  });

  it('profile update audit entry includes actor_id as the authenticated user', async () => {
    await physicianRequest('PUT', '/api/v1/providers/me', {
      specialty_code: 'SPEC',
    });

    const entry = findAuditEntry(ProviderAuditAction.PROFILE_UPDATED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
  });
});

// ===========================================================================
// AUDIT TRAIL — BA Events
// ===========================================================================

describe('Audit Trail — BA Events', () => {
  it('add BA produces ba.added audit entry with ba_number, ba_type, provider_id', async () => {
    const res = await physicianRequest('POST', '/api/v1/providers/me/bas', {
      ba_number: '99999',
      ba_type: 'FFS',
      effective_date: '2026-01-01',
    });

    expect(res.statusCode).toBeLessThan(500);

    const entry = findAuditEntry(ProviderAuditAction.BA_ADDED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('ba.added');
    expect(entry!.category).toBe('provider');
    expect(entry!.resourceType).toBe('business_arrangement');

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.providerId).toBe(PHYSICIAN_PROVIDER_ID);
    expect(detail.baNumber).toBe('99999');
    expect(detail.baType).toBe('FFS');
  });

  it('update BA produces ba.updated audit entry with changed fields', async () => {
    const res = await physicianRequest('PUT', `/api/v1/providers/me/bas/${BA_ID}`, {
      status: 'INACTIVE',
    });

    expect(res.statusCode).toBeLessThan(500);

    const entry = findAuditEntry(ProviderAuditAction.BA_UPDATED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('ba.updated');
    expect(entry!.resourceType).toBe('business_arrangement');
    expect(entry!.resourceId).toBe(BA_ID);

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.providerId).toBe(PHYSICIAN_PROVIDER_ID);
    expect(detail.changes).toBeDefined();
  });

  it('deactivate BA produces ba.deactivated audit entry with ba_number', async () => {
    const res = await physicianRequest('DELETE', `/api/v1/providers/me/bas/${BA_ID}`);

    expect(res.statusCode).toBeLessThan(500);

    const entry = findAuditEntry(ProviderAuditAction.BA_DEACTIVATED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('ba.deactivated');
    expect(entry!.resourceType).toBe('business_arrangement');
    expect(entry!.resourceId).toBe(BA_ID);

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.providerId).toBe(PHYSICIAN_PROVIDER_ID);
    expect(detail.baNumber).toBe('11111');
    expect(detail.baType).toBe('FFS');
  });
});

// ===========================================================================
// AUDIT TRAIL — Location Events
// ===========================================================================

describe('Audit Trail — Location Events', () => {
  it('add location produces location.added audit entry with name, functional_centre, provider_id', async () => {
    const res = await physicianRequest('POST', '/api/v1/providers/me/locations', {
      name: 'New Clinic',
      functional_centre: 'FC99',
    });

    expect(res.statusCode).toBeLessThan(500);

    const entry = findAuditEntry(ProviderAuditAction.LOCATION_ADDED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('location.added');
    expect(entry!.category).toBe('provider');
    expect(entry!.resourceType).toBe('practice_location');

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.providerId).toBe(PHYSICIAN_PROVIDER_ID);
    expect(detail.name).toBe('New Clinic');
    expect(detail.functionalCentre).toBe('FC99');
  });

  it('update location produces location.updated audit entry with changed fields', async () => {
    const res = await physicianRequest('PUT', `/api/v1/providers/me/locations/${LOCATION_ID}`, {
      name: 'Renamed Clinic',
    });

    expect(res.statusCode).toBeLessThan(500);

    const entry = findAuditEntry(ProviderAuditAction.LOCATION_UPDATED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('location.updated');
    expect(entry!.resourceType).toBe('practice_location');
    expect(entry!.resourceId).toBe(LOCATION_ID);

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.providerId).toBe(PHYSICIAN_PROVIDER_ID);
    expect(detail.changes).toBeDefined();
  });

  it('update location captures RRNP eligibility change in audit detail when community_code changes', async () => {
    // Update community code which triggers RRNP re-evaluation
    const res = await physicianRequest('PUT', `/api/v1/providers/me/locations/${LOCATION_ID}`, {
      community_code: 'RRNP-001',
    });

    expect(res.statusCode).toBeLessThan(500);

    const entry = findAuditEntry(ProviderAuditAction.LOCATION_UPDATED);
    expect(entry).toBeDefined();
    expect(entry!.action).toBe('location.updated');
    expect(entry!.resourceType).toBe('practice_location');
    expect(entry!.resourceId).toBe(LOCATION_ID);

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.providerId).toBe(PHYSICIAN_PROVIDER_ID);
    expect(detail.changes).toBeDefined();
    const changes = detail.changes as Record<string, { old: unknown; new: unknown }>;
    // communityCode should be in the changes
    expect(changes.communityCode).toBeDefined();
    expect(changes.communityCode.old).toBeNull();
    expect(changes.communityCode.new).toBe('RRNP-001');
  });

  it('set-default location produces location.updated audit entry with set_default action', async () => {
    const res = await physicianRequest('PUT', `/api/v1/providers/me/locations/${LOCATION_ID_2}/set-default`);

    expect(res.statusCode).toBeLessThan(500);

    const entries = findAuditEntries(ProviderAuditAction.LOCATION_UPDATED);
    const setDefaultEntry = entries.find((e) => {
      const d = e.detail as Record<string, unknown>;
      return d.action === 'set_default';
    });
    expect(setDefaultEntry).toBeDefined();
    expect(setDefaultEntry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(setDefaultEntry!.resourceId).toBe(LOCATION_ID_2);

    const detail = setDefaultEntry!.detail as Record<string, unknown>;
    expect(detail.newDefaultLocationId).toBe(LOCATION_ID_2);
  });

  it('deactivate location produces location.deactivated audit entry', async () => {
    // Deactivate the non-default location
    const res = await physicianRequest('DELETE', `/api/v1/providers/me/locations/${LOCATION_ID_2}`);

    expect(res.statusCode).toBeLessThan(500);

    const entry = findAuditEntry(ProviderAuditAction.LOCATION_DEACTIVATED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('location.deactivated');
    expect(entry!.resourceType).toBe('practice_location');
    expect(entry!.resourceId).toBe(LOCATION_ID_2);

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.providerId).toBe(PHYSICIAN_PROVIDER_ID);
  });
});

// ===========================================================================
// AUDIT TRAIL — WCB Config Events
// ===========================================================================

describe('Audit Trail — WCB Config Events', () => {
  it('add WCB config produces wcb_config.added audit entry with contract_id, role_code, provider_id', async () => {
    const res = await physicianRequest('POST', '/api/v1/providers/me/wcb', {
      contract_id: 'C002',
      role_code: 'R02',
    });

    expect(res.statusCode).toBeLessThan(500);

    const entry = findAuditEntry(ProviderAuditAction.WCB_CONFIG_ADDED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('wcb_config.added');
    expect(entry!.category).toBe('provider');
    expect(entry!.resourceType).toBe('wcb_configuration');

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.providerId).toBe(PHYSICIAN_PROVIDER_ID);
    expect(detail.contractId).toBe('C002');
    expect(detail.roleCode).toBe('R02');
  });

  it('update WCB config produces wcb_config.updated audit entry with changed fields', async () => {
    const res = await physicianRequest('PUT', `/api/v1/providers/me/wcb/${WCB_ID}`, {
      skill_code: 'S99',
    });

    expect(res.statusCode).toBeLessThan(500);

    const entry = findAuditEntry(ProviderAuditAction.WCB_CONFIG_UPDATED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('wcb_config.updated');
    expect(entry!.resourceType).toBe('wcb_configuration');
    expect(entry!.resourceId).toBe(WCB_ID);

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.providerId).toBe(PHYSICIAN_PROVIDER_ID);
    expect(detail.changes).toBeDefined();
  });

  it('remove WCB config produces wcb_config.removed audit entry with contract_id, role_code', async () => {
    const res = await physicianRequest('DELETE', `/api/v1/providers/me/wcb/${WCB_ID}`);

    expect(res.statusCode).toBeLessThan(500);

    const entry = findAuditEntry(ProviderAuditAction.WCB_CONFIG_REMOVED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('wcb_config.removed');
    expect(entry!.resourceType).toBe('wcb_configuration');
    expect(entry!.resourceId).toBe(WCB_ID);

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.providerId).toBe(PHYSICIAN_PROVIDER_ID);
    expect(detail.contractId).toBe('C001');
    expect(detail.roleCode).toBe('R01');
  });
});

// ===========================================================================
// AUDIT TRAIL — Delegate Events
// ===========================================================================

describe('Audit Trail — Delegate Events', () => {
  it('invite delegate produces delegate.invited audit entry with email and permissions', async () => {
    const res = await physicianRequest('POST', '/api/v1/providers/me/delegates/invite', {
      email: 'newdelegate@example.com',
      permissions: ['CLAIM_VIEW', 'PATIENT_VIEW'],
    });

    expect(res.statusCode).toBeLessThan(500);

    const entry = findAuditEntry(ProviderAuditAction.DELEGATE_INVITED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('delegate.invited');
    expect(entry!.category).toBe('provider');
    expect(entry!.resourceType).toBe('delegate_relationship');

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.physicianId).toBe(PHYSICIAN_PROVIDER_ID);
    expect(detail.delegateEmail).toBe('newdelegate@example.com');
    expect(detail.permissions).toEqual(['CLAIM_VIEW', 'PATIENT_VIEW']);
    expect(detail.expiresAt).toBeDefined();
  });

  it('invite delegate audit entry does NOT contain password or token hash', async () => {
    const res = await physicianRequest('POST', '/api/v1/providers/me/delegates/invite', {
      email: 'another@example.com',
      permissions: ['CLAIM_VIEW'],
    });

    expect(res.statusCode).toBeLessThan(500);

    const entry = findAuditEntry(ProviderAuditAction.DELEGATE_INVITED);
    expect(entry).toBeDefined();

    const detailStr = JSON.stringify(entry!.detail);
    expect(detailStr).not.toMatch(/password/i);
    expect(detailStr).not.toMatch(/tokenHash/i);
    expect(detailStr).not.toMatch(/rawToken/i);
  });

  it('update delegate permissions produces delegate.permissions_changed audit entry with old and new', async () => {
    const res = await physicianRequest('PUT', `/api/v1/providers/me/delegates/${DELEGATE_REL_ID}/permissions`, {
      permissions: ['CLAIM_VIEW', 'CLAIM_CREATE'],
    });

    expect(res.statusCode).toBeLessThan(500);

    const entry = findAuditEntry(ProviderAuditAction.DELEGATE_PERMISSIONS_CHANGED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('delegate.permissions_changed');
    expect(entry!.resourceType).toBe('delegate_relationship');
    expect(entry!.resourceId).toBe(DELEGATE_REL_ID);

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.physicianId).toBe(PHYSICIAN_PROVIDER_ID);
    expect(detail.oldPermissions).toEqual(['CLAIM_VIEW', 'PATIENT_VIEW']);
    expect(detail.newPermissions).toEqual(['CLAIM_VIEW', 'CLAIM_CREATE']);
    expect(detail.added).toBeDefined();
    expect(detail.removed).toBeDefined();
  });

  it('accept invitation produces delegate.accepted audit entry with delegate_user_id and physician_id', async () => {
    // First, invite a delegate to get a relationship ID
    const inviteRes = await physicianRequest('POST', '/api/v1/providers/me/delegates/invite', {
      email: 'accept-test@example.com',
      permissions: ['CLAIM_VIEW'],
    });
    expect(inviteRes.statusCode).toBeLessThan(500);

    const relationshipId = inviteRes.json().data.relationshipId;

    // Set up a known token in the token store for acceptance
    const knownRawToken = 'a'.repeat(64);
    const knownTokenHash = createHash('sha256').update(knownRawToken).digest('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);
    tokenStoreData[relationshipId] = { tokenHash: knownTokenHash, expiresAt };

    // Clear audit entries accumulated from the invite
    auditEntries.length = 0;

    // Accept the invitation via the unauthenticated endpoint
    const acceptRes = await app.inject({
      method: 'POST',
      url: `/api/v1/delegates/invitations/${relationshipId}/accept`,
      payload: { token: knownRawToken },
    });

    expect(acceptRes.statusCode).toBeLessThan(500);

    const entry = findAuditEntry(ProviderAuditAction.DELEGATE_ACCEPTED);
    expect(entry).toBeDefined();
    expect(entry!.action).toBe('delegate.accepted');
    expect(entry!.category).toBe('provider');
    expect(entry!.resourceType).toBe('delegate_relationship');
    expect(entry!.resourceId).toBe(relationshipId);

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.physicianId).toBe(PHYSICIAN_PROVIDER_ID);
    expect(detail.delegateUserId).toBeDefined();
    expect(detail.acceptedAt).toBeDefined();
  });

  it('revoke delegate produces delegate.revoked audit entry with delegate_user_id and actor', async () => {
    const res = await physicianRequest('POST', `/api/v1/providers/me/delegates/${DELEGATE_REL_ID}/revoke`);

    expect(res.statusCode).toBeLessThan(500);

    const entry = findAuditEntry(ProviderAuditAction.DELEGATE_REVOKED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('delegate.revoked');
    expect(entry!.resourceType).toBe('delegate_relationship');
    expect(entry!.resourceId).toBe(DELEGATE_REL_ID);

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.physicianId).toBe(PHYSICIAN_PROVIDER_ID);
    expect(detail.delegateUserId).toBe('99999999-0000-0000-0000-000000000099');
    expect(detail.previousStatus).toBe('ACTIVE');
  });
});

// ===========================================================================
// AUDIT TRAIL — Submission Preference / H-Link Events
// ===========================================================================

describe('Audit Trail — Preference and H-Link Events', () => {
  it('update submission preferences produces submission_preference.changed audit entry', async () => {
    const res = await physicianRequest('PUT', '/api/v1/providers/me/submission-preferences', {
      ahcip_submission_mode: 'REQUIRE_APPROVAL',
      wcb_submission_mode: 'REQUIRE_APPROVAL',
    });

    expect(res.statusCode).toBeLessThan(500);

    const entry = findAuditEntry(ProviderAuditAction.SUBMISSION_PREFERENCE_CHANGED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('submission_preference.changed');
    expect(entry!.category).toBe('provider');
    expect(entry!.resourceType).toBe('submission_preferences');
    expect(entry!.resourceId).toBe(PREF_ID);

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.providerId).toBe(PHYSICIAN_PROVIDER_ID);
    expect(detail.changes).toBeDefined();
  });

  it('update H-Link config produces hlink_config.updated audit entry', async () => {
    const res = await physicianRequest('PUT', '/api/v1/providers/me/hlink', {
      submitter_prefix: 'MER2',
    });

    expect(res.statusCode).toBeLessThan(500);

    const entry = findAuditEntry(ProviderAuditAction.HLINK_CONFIG_UPDATED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    expect(entry!.action).toBe('hlink_config.updated');
    expect(entry!.category).toBe('provider');
    expect(entry!.resourceType).toBe('hlink_configuration');
    expect(entry!.resourceId).toBe(HLINK_CONFIG_ID);

    const detail = entry!.detail as Record<string, unknown>;
    expect(detail.providerId).toBe(PHYSICIAN_PROVIDER_ID);
    expect(detail.changes).toBeDefined();
    const changes = detail.changes as Record<string, { old: unknown; new: unknown }>;
    expect(changes.submitterPrefix).toBeDefined();
    expect(changes.submitterPrefix.old).toBe('MER1');
    expect(changes.submitterPrefix.new).toBe('MER2');
  });

  it('H-Link audit entry does NOT contain credential values', async () => {
    await physicianRequest('PUT', '/api/v1/providers/me/hlink', {
      submitter_prefix: 'MER3',
    });

    const entry = findAuditEntry(ProviderAuditAction.HLINK_CONFIG_UPDATED);
    expect(entry).toBeDefined();

    const detailStr = JSON.stringify(entry);
    expect(detailStr).not.toContain('credential');
    expect(detailStr).not.toContain('vault://');
    expect(detailStr).not.toContain('secret');
    expect(detailStr).not.toContain('credentialSecretRef');
  });
});

// ===========================================================================
// AUDIT TRAIL — Entry Structure Verification
// ===========================================================================

describe('Audit Trail — Entry Structure', () => {
  it('every audit entry includes action, actor_id, timestamp fields, resource_id, and detail', async () => {
    // Trigger a state change
    await physicianRequest('PUT', '/api/v1/providers/me', {
      first_name: 'StructureTest',
    });

    const entry = findAuditEntry(ProviderAuditAction.PROFILE_UPDATED);
    expect(entry).toBeDefined();

    // Required fields per audit_log schema
    expect(entry!.action).toBeDefined();
    expect(typeof entry!.action).toBe('string');
    expect(entry!.userId).toBeDefined();
    expect(typeof entry!.userId).toBe('string');
    expect(entry!.category).toBeDefined();
    expect(typeof entry!.category).toBe('string');
    expect(entry!.resourceType).toBeDefined();
    expect(entry!.resourceId).toBeDefined();
    expect(entry!.detail).toBeDefined();
    expect(typeof entry!.detail).toBe('object');
  });

  it('actor_id is the authenticated physician, not a system user', async () => {
    await physicianRequest('POST', '/api/v1/providers/me/bas', {
      ba_number: '77777',
      ba_type: 'FFS',
      effective_date: '2026-06-01',
    });

    const entry = findAuditEntry(ProviderAuditAction.BA_ADDED);
    expect(entry).toBeDefined();
    expect(entry!.userId).toBe(PHYSICIAN_USER_ID);
    // Not a system user ID like 'system' or '00000000-...'
    expect(entry!.userId).not.toBe('system');
    expect(entry!.userId).not.toBe('00000000-0000-0000-0000-000000000000');
  });

  it('audit detail is JSONB-compatible (plain object, no functions or class instances)', async () => {
    await physicianRequest('DELETE', `/api/v1/providers/me/bas/${BA_ID}`);

    const entry = findAuditEntry(ProviderAuditAction.BA_DEACTIVATED);
    expect(entry).toBeDefined();

    const detail = entry!.detail;
    // Should survive JSON round-trip without loss
    const serialized = JSON.stringify(detail);
    const deserialized = JSON.parse(serialized);
    expect(deserialized).toEqual(detail);
  });
});

// ===========================================================================
// AUDIT TRAIL — Append-Only Integrity
// ===========================================================================

describe('Audit Trail — Append-Only Integrity', () => {
  it('no UPDATE endpoint exists for audit_log in this domain', async () => {
    // Attempt to PUT to a hypothetical audit endpoint
    const res = await physicianRequest('PUT', '/api/v1/providers/me/audit-log/some-id');
    // Should be 404 — the route doesn't exist
    expect(res.statusCode).toBe(404);
  });

  it('no DELETE endpoint exists for audit_log in this domain', async () => {
    // Attempt to DELETE to a hypothetical audit endpoint
    const res = await physicianRequest('DELETE', '/api/v1/providers/me/audit-log/some-id');
    // Should be 404 — the route doesn't exist
    expect(res.statusCode).toBe(404);
  });

  it('audit log entries accumulate without overwriting previous entries', async () => {
    // Perform multiple actions
    await physicianRequest('PUT', '/api/v1/providers/me', { first_name: 'First' });
    await physicianRequest('PUT', '/api/v1/providers/me', { first_name: 'Second' });

    const entries = findAuditEntries(ProviderAuditAction.PROFILE_UPDATED);
    // Both entries should be present — append-only
    expect(entries.length).toBe(2);
    const detail0 = entries[0].detail as Record<string, unknown>;
    const detail1 = entries[1].detail as Record<string, unknown>;
    const changes0 = detail0.changes as Record<string, { old: unknown; new: unknown }>;
    const changes1 = detail1.changes as Record<string, { old: unknown; new: unknown }>;
    expect(changes0.firstName.new).toBe('First');
    expect(changes1.firstName.new).toBe('Second');
  });
});

// ===========================================================================
// AUDIT TRAIL — Sensitive Data Exclusion
// ===========================================================================

describe('Audit Trail — Sensitive Data Exclusion', () => {
  it('no audit entry contains password hashes', async () => {
    // Trigger several actions
    await physicianRequest('PUT', '/api/v1/providers/me', { first_name: 'Test' });
    await physicianRequest('POST', '/api/v1/providers/me/bas', {
      ba_number: '88888',
      ba_type: 'FFS',
      effective_date: '2026-01-01',
    });

    for (const entry of auditEntries) {
      const str = JSON.stringify(entry);
      expect(str).not.toMatch(/passwordHash/i);
      expect(str).not.toMatch(/password_hash/i);
    }
  });

  it('no audit entry contains credential secrets', async () => {
    await physicianRequest('PUT', '/api/v1/providers/me/hlink', {
      submitter_prefix: 'MERX',
    });

    for (const entry of auditEntries) {
      const str = JSON.stringify(entry);
      expect(str).not.toContain('credentialSecretRef');
      expect(str).not.toContain('credential_secret_ref');
      expect(str).not.toContain('vault://');
    }
  });

  it('delegate invite audit entry does not contain invitation token', async () => {
    await physicianRequest('POST', '/api/v1/providers/me/delegates/invite', {
      email: 'secret-test@example.com',
      permissions: ['CLAIM_VIEW'],
    });

    const entry = findAuditEntry(ProviderAuditAction.DELEGATE_INVITED);
    expect(entry).toBeDefined();

    const detailStr = JSON.stringify(entry!.detail);
    expect(detailStr).not.toMatch(/rawToken/i);
    expect(detailStr).not.toMatch(/tokenHash/i);
  });
});
