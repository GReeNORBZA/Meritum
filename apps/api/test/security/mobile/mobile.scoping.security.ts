// ============================================================================
// Domain 10: Mobile Companion — Cross-Physician Tenant Isolation (Security)
//
// MOST CRITICAL security test for Domain 10.
// Shifts contain patient encounters (PHI-adjacent). Favourites are
// physician-specific. Quick claims reference patients. Summary KPIs
// are per-physician. Every cross-physician access MUST return 404, NEVER 403.
//
// Test identities:
//   - Physician A: owns shifts, favourites, claims, patients
//   - Physician B: owns separate shifts, favourites, claims, patients
//   - Delegate: linked to Physician A only, has CLAIM_VIEW + CLAIM_CREATE
//
// Coverage:
//   - Shift isolation (active, summary, end, patients, list)
//   - Favourite isolation (list, update, delete, reorder)
//   - Quick claim isolation (cross-tenant patient)
//   - Recent patients isolation
//   - Mobile summary isolation
//   - Delegate cross-physician isolation
// ============================================================================

import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Environment setup (must be before imports that read env)
// ---------------------------------------------------------------------------

process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Mock otplib (required by iam.service.ts transitive import)
// ---------------------------------------------------------------------------

vi.mock('otplib', () => ({
  authenticator: {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn(() => 'otpauth://totp/test'),
    verify: vi.fn(() => false),
  },
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import {
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { authPluginFp } from '../../../src/plugins/auth.plugin.js';
import { shiftRoutes } from '../../../src/domains/mobile/routes/shift.routes.js';
import { favouriteRoutes } from '../../../src/domains/mobile/routes/favourite.routes.js';
import { mobileRoutes } from '../../../src/domains/mobile/routes/mobile.routes.js';
import type { ShiftRouteDeps } from '../../../src/domains/mobile/routes/shift.routes.js';
import type { FavouriteRouteDeps } from '../../../src/domains/mobile/routes/favourite.routes.js';
import type { MobileRouteDeps } from '../../../src/domains/mobile/routes/mobile.routes.js';
import {
  type SessionManagementDeps,
  hashToken,
} from '../../../src/domains/iam/iam.service.js';
import { resetAuditRateLimiter } from '../../../src/domains/mobile/services/mobile-summary.service.js';

// ---------------------------------------------------------------------------
// Fixed test identities — Two isolated physicians + delegate
// ---------------------------------------------------------------------------

// Physician A — "our" physician
const PA_SESSION_TOKEN = randomBytes(32).toString('hex');
const PA_SESSION_TOKEN_HASH = hashToken(PA_SESSION_TOKEN);
const PA_USER_ID = '11111111-aaaa-0000-0000-000000000001';
const PA_PROVIDER_ID = PA_USER_ID;
const PA_SESSION_ID = '11111111-aaaa-0000-0000-000000000011';

// Physician B — "other" physician (attacker perspective)
const PB_SESSION_TOKEN = randomBytes(32).toString('hex');
const PB_SESSION_TOKEN_HASH = hashToken(PB_SESSION_TOKEN);
const PB_USER_ID = '22222222-bbbb-0000-0000-000000000002';
const PB_PROVIDER_ID = PB_USER_ID;
const PB_SESSION_ID = '22222222-bbbb-0000-0000-000000000022';

// Delegate linked to Physician A only (CLAIM_VIEW + CLAIM_CREATE)
const DELEGATE_SESSION_TOKEN = randomBytes(32).toString('hex');
const DELEGATE_SESSION_TOKEN_HASH = hashToken(DELEGATE_SESSION_TOKEN);
const DELEGATE_USER_ID = '33333333-dddd-0000-0000-000000000003';
const DELEGATE_SESSION_ID = '33333333-dddd-0000-0000-000000000033';

// ---------------------------------------------------------------------------
// Test data IDs — resources owned by each physician
// ---------------------------------------------------------------------------

// Physician A's resources
const PA_SHIFT_ID = 'aaaa0001-0000-0000-0000-000000000001';
const PA_FAVOURITE_ID_1 = 'aaaa0002-0000-0000-0000-000000000001';
const PA_FAVOURITE_ID_2 = 'aaaa0002-0000-0000-0000-000000000002';
const PA_PATIENT_ID = 'aaaa0003-0000-0000-0000-000000000001';
const PA_CLAIM_ID = 'aaaa0004-0000-0000-0000-000000000001';
const PA_LOCATION_ID = 'aaaa0005-0000-0000-0000-000000000001';

// Physician B's resources
const PB_SHIFT_ID = 'bbbb0001-0000-0000-0000-000000000001';
const PB_FAVOURITE_ID_1 = 'bbbb0002-0000-0000-0000-000000000001';
const PB_FAVOURITE_ID_2 = 'bbbb0002-0000-0000-0000-000000000002';
const PB_PATIENT_ID = 'bbbb0003-0000-0000-0000-000000000001';
const PB_CLAIM_ID = 'bbbb0004-0000-0000-0000-000000000001';
const PB_LOCATION_ID = 'bbbb0005-0000-0000-0000-000000000001';

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
// In-memory data stores (physician-scoped)
// ---------------------------------------------------------------------------

interface MockShift {
  shiftId: string;
  providerId: string;
  locationId: string;
  shiftStart: Date;
  shiftEnd: Date | null;
  status: string;
  patientCount: number;
  estimatedValue: string;
  createdAt: Date;
  updatedAt: Date;
}

interface MockFavourite {
  favouriteId: string;
  providerId: string;
  healthServiceCode: string;
  displayName: string | null;
  sortOrder: number;
  defaultModifiers: string[] | null;
  createdAt: Date;
}

interface MockPatient {
  patientId: string;
  providerId: string;
  firstName: string;
  lastName: string;
  phn: string;
  dateOfBirth: string;
  gender: string;
}

interface MockClaim {
  claimId: string;
  providerId: string;
  patientId: string;
  healthServiceCode: string;
  dateOfService: string;
}

const shiftsStore: Record<string, MockShift> = {};
const favouritesStore: Record<string, MockFavourite> = {};
const patientsStore: Record<string, MockPatient> = {};
const claimsStore: Record<string, MockClaim> = {};

function seedTestData() {
  Object.keys(shiftsStore).forEach((k) => delete shiftsStore[k]);
  Object.keys(favouritesStore).forEach((k) => delete favouritesStore[k]);
  Object.keys(patientsStore).forEach((k) => delete patientsStore[k]);
  Object.keys(claimsStore).forEach((k) => delete claimsStore[k]);

  // --- Physician A's shifts ---
  shiftsStore[PA_SHIFT_ID] = {
    shiftId: PA_SHIFT_ID,
    providerId: PA_PROVIDER_ID,
    locationId: PA_LOCATION_ID,
    shiftStart: new Date('2026-02-19T08:00:00Z'),
    shiftEnd: null,
    status: 'ACTIVE',
    patientCount: 3,
    estimatedValue: '150.00',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- Physician B's shifts ---
  shiftsStore[PB_SHIFT_ID] = {
    shiftId: PB_SHIFT_ID,
    providerId: PB_PROVIDER_ID,
    locationId: PB_LOCATION_ID,
    shiftStart: new Date('2026-02-19T09:00:00Z'),
    shiftEnd: null,
    status: 'ACTIVE',
    patientCount: 5,
    estimatedValue: '250.00',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // --- Physician A's favourites ---
  favouritesStore[PA_FAVOURITE_ID_1] = {
    favouriteId: PA_FAVOURITE_ID_1,
    providerId: PA_PROVIDER_ID,
    healthServiceCode: '03.04A',
    displayName: 'Office Visit',
    sortOrder: 1,
    defaultModifiers: null,
    createdAt: new Date(),
  };
  favouritesStore[PA_FAVOURITE_ID_2] = {
    favouriteId: PA_FAVOURITE_ID_2,
    providerId: PA_PROVIDER_ID,
    healthServiceCode: '03.05A',
    displayName: 'Consultation',
    sortOrder: 2,
    defaultModifiers: null,
    createdAt: new Date(),
  };

  // --- Physician B's favourites ---
  favouritesStore[PB_FAVOURITE_ID_1] = {
    favouriteId: PB_FAVOURITE_ID_1,
    providerId: PB_PROVIDER_ID,
    healthServiceCode: '08.19A',
    displayName: 'ED Visit',
    sortOrder: 1,
    defaultModifiers: null,
    createdAt: new Date(),
  };
  favouritesStore[PB_FAVOURITE_ID_2] = {
    favouriteId: PB_FAVOURITE_ID_2,
    providerId: PB_PROVIDER_ID,
    healthServiceCode: '08.11A',
    displayName: 'Trauma',
    sortOrder: 2,
    defaultModifiers: null,
    createdAt: new Date(),
  };

  // --- Physician A's patients ---
  patientsStore[PA_PATIENT_ID] = {
    patientId: PA_PATIENT_ID,
    providerId: PA_PROVIDER_ID,
    firstName: 'Alice',
    lastName: 'Smith',
    phn: '123456789',
    dateOfBirth: '1980-01-15',
    gender: 'F',
  };

  // --- Physician B's patients ---
  patientsStore[PB_PATIENT_ID] = {
    patientId: PB_PATIENT_ID,
    providerId: PB_PROVIDER_ID,
    firstName: 'Charlie',
    lastName: 'Brown',
    phn: '987654321',
    dateOfBirth: '1975-03-10',
    gender: 'M',
  };

  // --- Physician A's claims ---
  claimsStore[PA_CLAIM_ID] = {
    claimId: PA_CLAIM_ID,
    providerId: PA_PROVIDER_ID,
    patientId: PA_PATIENT_ID,
    healthServiceCode: '03.04A',
    dateOfService: '2026-02-19',
  };

  // --- Physician B's claims ---
  claimsStore[PB_CLAIM_ID] = {
    claimId: PB_CLAIM_ID,
    providerId: PB_PROVIDER_ID,
    patientId: PB_PATIENT_ID,
    healthServiceCode: '08.19A',
    dateOfService: '2026-02-19',
  };
}

// ---------------------------------------------------------------------------
// Mock repositories (provider-scoped — the core of tenant isolation)
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

/**
 * Shift repo mock with strict provider scoping.
 * getById, endShift, getSummary, list, getActive, logPatient —
 * all filter by providerId. Cross-tenant returns null/empty.
 */
function createScopedShiftRepo() {
  return {
    create: vi.fn(async (data: any) => {
      const shift: MockShift = {
        shiftId: crypto.randomUUID(),
        providerId: data.providerId,
        locationId: data.locationId,
        shiftStart: data.shiftStart,
        shiftEnd: null,
        status: 'ACTIVE',
        patientCount: 0,
        estimatedValue: '0.00',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      shiftsStore[shift.shiftId] = shift;
      return shift;
    }),

    findActive: vi.fn(async (providerId: string) => {
      return (
        Object.values(shiftsStore).find(
          (s) => s.providerId === providerId && s.status === 'ACTIVE',
        ) ?? null
      );
    }),

    getActive: vi.fn(async (providerId: string) => {
      return (
        Object.values(shiftsStore).find(
          (s) => s.providerId === providerId && s.status === 'ACTIVE',
        ) ?? null
      );
    }),

    getById: vi.fn(async (shiftId: string, providerId: string) => {
      const shift = shiftsStore[shiftId];
      if (!shift || shift.providerId !== providerId) return null;
      return shift;
    }),

    endShift: vi.fn(async (shiftId: string, providerId: string) => {
      const shift = shiftsStore[shiftId];
      if (!shift || shift.providerId !== providerId) return null;
      shift.status = 'COMPLETED';
      shift.shiftEnd = new Date();
      shift.updatedAt = new Date();
      return shift;
    }),

    getSummary: vi.fn(async (shiftId: string, providerId: string) => {
      const shift = shiftsStore[shiftId];
      if (!shift || shift.providerId !== providerId) return null;
      return {
        shiftId: shift.shiftId,
        providerId: shift.providerId,
        locationId: shift.locationId,
        shiftStart: shift.shiftStart,
        shiftEnd: shift.shiftEnd,
        status: shift.status,
        patientCount: shift.patientCount,
        estimatedValue: shift.estimatedValue,
        claims: Object.values(claimsStore).filter(
          (c) => c.providerId === providerId,
        ),
      };
    }),

    list: vi.fn(async (providerId: string, _filters?: any) => {
      const data = Object.values(shiftsStore).filter(
        (s) => s.providerId === providerId,
      );
      return { data, total: data.length };
    }),

    listByProvider: vi.fn(async (providerId: string, _filters?: any) => {
      const data = Object.values(shiftsStore).filter(
        (s) => s.providerId === providerId,
      );
      return { data, total: data.length };
    }),

    logPatient: vi.fn(async (shiftId: string, providerId: string, _data: any) => {
      const shift = shiftsStore[shiftId];
      if (!shift || shift.providerId !== providerId) return null;
      shift.patientCount += 1;
      return shift;
    }),

    incrementPatientCount: vi.fn(async (shiftId: string, providerId: string, _feeAmount: string) => {
      const shift = shiftsStore[shiftId];
      if (!shift || shift.providerId !== providerId) return null;
      shift.patientCount += 1;
      return shift;
    }),

    getShiftSummary: vi.fn(async (shiftId: string, providerId: string) => {
      const shift = shiftsStore[shiftId];
      if (!shift || shift.providerId !== providerId) return null;
      return {
        shiftId: shift.shiftId,
        providerId: shift.providerId,
        locationId: shift.locationId,
        shiftStart: shift.shiftStart,
        shiftEnd: shift.shiftEnd,
        status: shift.status,
        patientCount: shift.patientCount,
        estimatedValue: shift.estimatedValue,
        claims: [],
      };
    }),
  };
}

/**
 * Favourite repo mock with strict provider scoping.
 */
function createScopedFavouriteRepo() {
  return {
    create: vi.fn(async (data: any) => {
      const fav: MockFavourite = {
        favouriteId: crypto.randomUUID(),
        providerId: data.providerId,
        healthServiceCode: data.healthServiceCode,
        displayName: data.displayName ?? null,
        sortOrder: data.sortOrder,
        defaultModifiers: data.defaultModifiers ?? null,
        createdAt: new Date(),
      };
      favouritesStore[fav.favouriteId] = fav;
      return fav;
    }),

    findById: vi.fn(async (favouriteId: string, providerId: string) => {
      const fav = favouritesStore[favouriteId];
      if (!fav || fav.providerId !== providerId) return null;
      return fav;
    }),

    update: vi.fn(async (favouriteId: string, providerId: string, data: any) => {
      const fav = favouritesStore[favouriteId];
      if (!fav || fav.providerId !== providerId) return null;
      if (data.displayName !== undefined) fav.displayName = data.displayName;
      if (data.sortOrder !== undefined) fav.sortOrder = data.sortOrder;
      if (data.defaultModifiers !== undefined) fav.defaultModifiers = data.defaultModifiers;
      return fav;
    }),

    delete: vi.fn(async (favouriteId: string, providerId: string) => {
      const fav = favouritesStore[favouriteId];
      if (!fav || fav.providerId !== providerId) return null;
      delete favouritesStore[favouriteId];
      return fav;
    }),

    listByProvider: vi.fn(async (providerId: string) => {
      return Object.values(favouritesStore)
        .filter((f) => f.providerId === providerId)
        .sort((a, b) => a.sortOrder - b.sortOrder);
    }),

    countByProvider: vi.fn(async (providerId: string) => {
      return Object.values(favouritesStore).filter(
        (f) => f.providerId === providerId,
      ).length;
    }),

    reorder: vi.fn(async (providerId: string, items: Array<{ favourite_id: string; sort_order: number }>) => {
      // Validate ALL items belong to provider — this is the critical check
      for (const item of items) {
        const fav = favouritesStore[item.favourite_id];
        if (!fav || fav.providerId !== providerId) {
          throw new Error('Favourite not found');
        }
      }
      for (const item of items) {
        const fav = favouritesStore[item.favourite_id];
        if (fav) {
          fav.sortOrder = item.sort_order;
        }
      }
    }),

    bulkCreate: vi.fn(async (providerId: string, items: any[]) => {
      return items.map((item) => {
        const fav: MockFavourite = {
          favouriteId: crypto.randomUUID(),
          providerId,
          healthServiceCode: item.healthServiceCode,
          displayName: item.displayName ?? null,
          sortOrder: item.sortOrder,
          defaultModifiers: item.defaultModifiers ?? null,
          createdAt: new Date(),
        };
        favouritesStore[fav.favouriteId] = fav;
        return fav;
      });
    }),
  };
}

/**
 * Claim repo mock for quick claim creation with provider scoping.
 */
function createScopedClaimRepo() {
  return {
    createDraftClaim: vi.fn(async (providerId: string, data: any) => {
      // Validate patient belongs to provider (tenant isolation)
      const patient = patientsStore[data.patientId];
      if (!patient || patient.providerId !== providerId) {
        const err: any = new Error('Resource not found');
        err.statusCode = 404;
        err.code = 'NOT_FOUND';
        throw err;
      }
      const claimId = crypto.randomUUID();
      claimsStore[claimId] = {
        claimId,
        providerId,
        patientId: data.patientId,
        healthServiceCode: data.healthServiceCode,
        dateOfService: data.dateOfService,
      };
      return { claimId };
    }),
  };
}

/**
 * Patient repo mock for mobile patient creation and recent patients query.
 */
function createScopedPatientRepo() {
  return {
    create: vi.fn(async (data: any) => {
      const patientId = crypto.randomUUID();
      const patient: MockPatient = {
        patientId,
        providerId: data.providerId,
        firstName: data.firstName,
        lastName: data.lastName,
        phn: data.phn,
        dateOfBirth: data.dateOfBirth,
        gender: data.gender,
      };
      patientsStore[patientId] = patient;
      return patient;
    }),

    findByProvider: vi.fn(async (providerId: string) => {
      return Object.values(patientsStore).filter(
        (p) => p.providerId === providerId,
      );
    }),

    findById: vi.fn(async (patientId: string, providerId: string) => {
      const patient = patientsStore[patientId];
      if (!patient || patient.providerId !== providerId) return null;
      return patient;
    }),

    getRecentByProvider: vi.fn(async (providerId: string, limit: number) => {
      return Object.values(patientsStore)
        .filter((p) => p.providerId === providerId)
        .slice(0, limit);
    }),
  };
}

/**
 * Summary repo mock with provider scoping on all counts.
 */
function createScopedSummaryRepo() {
  return {
    getTodayCounts: vi.fn(async (physicianId: string, _todayStart: Date) => {
      return Object.values(claimsStore).filter(
        (c) => c.providerId === physicianId,
      ).length;
    }),

    getWeekRevenue: vi.fn(async (_physicianId: string) => '0.00'),

    getActiveShift: vi.fn(async (providerId: string) => {
      return (
        Object.values(shiftsStore).find(
          (s) => s.providerId === providerId && s.status === 'ACTIVE',
        ) ?? null
      );
    }),

    getPendingCount: vi.fn(async (_physicianId: string) => 0),
  };
}

// ---------------------------------------------------------------------------
// Mock session/audit/events infrastructure
// ---------------------------------------------------------------------------

function createMockAuditRepo() {
  return { appendAuditLog: vi.fn(async () => {}) };
}

function createMockEvents() {
  return { emit: vi.fn() };
}

// ---------------------------------------------------------------------------
// Build test dependencies
// ---------------------------------------------------------------------------

let shiftRepo: ReturnType<typeof createScopedShiftRepo>;
let favouriteRepo: ReturnType<typeof createScopedFavouriteRepo>;
let claimRepo: ReturnType<typeof createScopedClaimRepo>;
let patientRepo: ReturnType<typeof createScopedPatientRepo>;
let summaryRepo: ReturnType<typeof createScopedSummaryRepo>;

function createShiftDeps(): ShiftRouteDeps {
  return {
    serviceDeps: {
      repo: shiftRepo,
      locationCheck: {
        belongsToPhysician: vi.fn(async (locationId: string, physicianId: string) => {
          // Physician A's location only belongs to Physician A
          if (locationId === PA_LOCATION_ID && physicianId === PA_PROVIDER_ID) return true;
          if (locationId === PB_LOCATION_ID && physicianId === PB_PROVIDER_ID) return true;
          return false;
        }),
      },
      claimCreator: {
        createClaimFromShift: vi.fn(async (physicianId: string, _actorId: string, _shiftId: string, data: any) => {
          const claimId = crypto.randomUUID();
          claimsStore[claimId] = {
            claimId,
            providerId: physicianId,
            patientId: data.patientId,
            healthServiceCode: '03.04A',
            dateOfService: data.dateOfService,
          };
          return { claimId };
        }),
      },
      auditRepo: createMockAuditRepo(),
    } as any,
  };
}

function createFavouriteDeps(): FavouriteRouteDeps {
  return {
    serviceDeps: {
      repo: favouriteRepo,
      hscLookup: {
        findByCode: vi.fn(async (code: string) => ({
          code,
          description: `Procedure ${code}`,
          baseFee: '50.00',
          feeType: 'FIXED',
        })),
      },
      modifierLookup: {
        isKnownModifier: vi.fn(async () => true),
      },
      claimHistory: {
        getTopBilledCodes: vi.fn(async () => []),
      },
      providerProfile: {
        getSpecialty: vi.fn(async () => null),
      },
      specialtyDefaults: {
        getDefaultCodes: vi.fn(async () => []),
      },
      auditRepo: createMockAuditRepo(),
    } as any,
  };
}

function createMobileDeps(): MobileRouteDeps {
  return {
    quickClaimServiceDeps: {
      claimCreator: claimRepo,
      patientCreator: {
        createMinimalPatient: vi.fn(async (providerId: string, data: any) => {
          const patientId = crypto.randomUUID();
          const patient = {
            patientId,
            firstName: data.firstName,
            lastName: data.lastName,
            phn: data.phn,
            dateOfBirth: data.dateOfBirth,
            gender: data.gender,
          };
          patientsStore[patientId] = { ...patient, providerId };
          return patient;
        }),
      },
      recentPatientsQuery: {
        getRecentBilledPatients: vi.fn(async (providerId: string, limit: number) => {
          // Returns only the authenticated physician's recently billed patients
          return Object.values(patientsStore)
            .filter((p) => p.providerId === providerId)
            .slice(0, limit)
            .map((p) => ({
              patientId: p.patientId,
              firstName: p.firstName,
              lastName: p.lastName,
              phn: p.phn,
            }));
        }),
      },
      auditRepo: createMockAuditRepo(),
    } as any,
    summaryServiceDeps: {
      claimCounter: {
        countTodayClaims: vi.fn(async (physicianId: string, _todayStart: Date) => {
          return Object.values(claimsStore).filter(
            (c) => c.providerId === physicianId,
          ).length;
        }),
        countPendingQueue: vi.fn(async (_physicianId: string) => 0),
      },
      unreadCounter: {
        countUnread: vi.fn(async (_recipientId: string) => 0),
      },
      activeShiftLookup: {
        getActive: vi.fn(async (providerId: string) => {
          return (
            Object.values(shiftsStore).find(
              (s) => s.providerId === providerId && s.status === 'ACTIVE',
            ) ?? null
          );
        }),
      },
      auditRepo: createMockAuditRepo(),
    } as any,
  };
}

// ---------------------------------------------------------------------------
// Seed users and sessions
// ---------------------------------------------------------------------------

function seedUsers() {
  users = [];
  sessions = [];

  // Physician A
  users.push({
    userId: PA_USER_ID,
    email: 'physician-a@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: PA_SESSION_ID,
    userId: PA_USER_ID,
    tokenHash: PA_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Physician B
  users.push({
    userId: PB_USER_ID,
    email: 'physician-b@example.com',
    passwordHash: 'hashed',
    mfaConfigured: true,
    totpSecretEncrypted: null,
    failedLoginCount: 0,
    lockedUntil: null,
    isActive: true,
    role: 'PHYSICIAN',
    subscriptionStatus: 'ACTIVE',
  });
  sessions.push({
    sessionId: PB_SESSION_ID,
    userId: PB_USER_ID,
    tokenHash: PB_SESSION_TOKEN_HASH,
    ipAddress: '127.0.0.1',
    userAgent: 'test-agent',
    createdAt: new Date(),
    lastActiveAt: new Date(),
    revoked: false,
    revokedReason: null,
  });

  // Delegate linked to Physician A (CLAIM_VIEW + CLAIM_CREATE)
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
    subscriptionStatus: 'ACTIVE',
    delegateContext: {
      delegateUserId: DELEGATE_USER_ID,
      physicianProviderId: PA_PROVIDER_ID,
      permissions: ['CLAIM_VIEW', 'CLAIM_CREATE', 'PATIENT_VIEW', 'PATIENT_CREATE'],
      linkageId: 'eeeeeeee-0000-0000-0000-000000000001',
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

  shiftRepo = createScopedShiftRepo();
  favouriteRepo = createScopedFavouriteRepo();
  claimRepo = createScopedClaimRepo();
  patientRepo = createScopedPatientRepo();
  summaryRepo = createScopedSummaryRepo();

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, _request, reply) => {
    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      const message = error.statusCode === 404 ? 'Resource not found' : error.message;
      return reply.code(error.statusCode).send({
        error: { code: (error as any).code ?? 'ERROR', message },
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

  await testApp.register(shiftRoutes, { deps: createShiftDeps() });
  await testApp.register(favouriteRoutes, { deps: createFavouriteDeps() });
  await testApp.register(mobileRoutes, { deps: createMobileDeps() });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function physicianARequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${PA_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function physicianBRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${PB_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function delegateRequest(method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${DELEGATE_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

describe('Mobile Companion Cross-Physician Tenant Isolation (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsers();
    seedTestData();
    resetAuditRateLimiter();
  });

  // =========================================================================
  // 1. Shift Isolation — Active Shift
  // =========================================================================

  describe('Shift isolation — active shift', () => {
    it('Physician A sees own active shift', async () => {
      const res = await physicianARequest('GET', '/api/v1/shifts/active');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.shiftId).toBe(PA_SHIFT_ID);
      expect(body.data.providerId).toBe(PA_PROVIDER_ID);
    });

    it('Physician B sees own active shift, not Physician A\'s', async () => {
      const res = await physicianBRequest('GET', '/api/v1/shifts/active');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.shiftId).toBe(PB_SHIFT_ID);
      expect(body.data.providerId).toBe(PB_PROVIDER_ID);
      // Must NOT be Physician A's shift
      expect(body.data.shiftId).not.toBe(PA_SHIFT_ID);
    });

    it('Physician B with no active shift gets 204, not Physician A\'s shift', async () => {
      // End Physician B's shift
      delete shiftsStore[PB_SHIFT_ID];
      const res = await physicianBRequest('GET', '/api/v1/shifts/active');
      expect(res.statusCode).toBe(204);
      // Physician A's shift must not leak
      expect(res.body).toBe('');
    });
  });

  // =========================================================================
  // 2. Shift Isolation — Get Summary by ID
  // =========================================================================

  describe('Shift isolation — summary by ID', () => {
    it('Physician A can get own shift summary', async () => {
      const res = await physicianARequest('GET', `/api/v1/shifts/${PA_SHIFT_ID}/summary`);
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.shiftId).toBe(PA_SHIFT_ID);
    });

    it('Physician B cannot get Physician A\'s shift summary — returns 404 not 403', async () => {
      const res = await physicianBRequest('GET', `/api/v1/shifts/${PA_SHIFT_ID}/summary`);
      expect(res.statusCode).toBe(404);
      // Must NOT return 403 (would confirm existence)
      expect(res.statusCode).not.toBe(403);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
      // Error message must not leak shift details
      expect(body.error.message).not.toContain(PA_SHIFT_ID);
    });

    it('Physician A cannot get Physician B\'s shift summary — returns 404 not 403', async () => {
      const res = await physicianARequest('GET', `/api/v1/shifts/${PB_SHIFT_ID}/summary`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 3. Shift Isolation — End Shift
  // =========================================================================

  describe('Shift isolation — end shift', () => {
    it('Physician B cannot end Physician A\'s shift — returns 404 not 403', async () => {
      const res = await physicianBRequest('POST', `/api/v1/shifts/${PA_SHIFT_ID}/end`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
      // Verify shift was NOT actually ended
      expect(shiftsStore[PA_SHIFT_ID].status).toBe('ACTIVE');
    });

    it('Physician A cannot end Physician B\'s shift — returns 404 not 403', async () => {
      const res = await physicianARequest('POST', `/api/v1/shifts/${PB_SHIFT_ID}/end`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
      expect(shiftsStore[PB_SHIFT_ID].status).toBe('ACTIVE');
    });

    it('Physician A can end own shift', async () => {
      const res = await physicianARequest('POST', `/api/v1/shifts/${PA_SHIFT_ID}/end`);
      expect(res.statusCode).toBe(200);
      expect(shiftsStore[PA_SHIFT_ID].status).toBe('COMPLETED');
    });
  });

  // =========================================================================
  // 4. Shift Isolation — Log Patient in Shift
  // =========================================================================

  describe('Shift isolation — log patient in shift', () => {
    const logPayload = {
      patient_id: PA_PATIENT_ID,
      health_service_code: '03.04A',
      date_of_service: '2026-02-19',
    };

    it('Physician B cannot log patient to Physician A\'s shift — returns 404 not 403', async () => {
      const res = await physicianBRequest(
        'POST',
        `/api/v1/shifts/${PA_SHIFT_ID}/patients`,
        logPayload,
      );
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
      // Patient count must not have changed
      expect(shiftsStore[PA_SHIFT_ID].patientCount).toBe(3);
    });

    it('Physician A cannot log patient to Physician B\'s shift — returns 404 not 403', async () => {
      const res = await physicianARequest(
        'POST',
        `/api/v1/shifts/${PB_SHIFT_ID}/patients`,
        { ...logPayload, patient_id: PB_PATIENT_ID },
      );
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });
  });

  // =========================================================================
  // 5. Shift Isolation — List Shifts
  // =========================================================================

  describe('Shift isolation — list shifts', () => {
    it('Physician A sees only own shifts in list', async () => {
      const res = await physicianARequest('GET', '/api/v1/shifts');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      for (const shift of body.data) {
        expect(shift.providerId).toBe(PA_PROVIDER_ID);
      }
      // Must NOT contain Physician B's shift
      const shiftIds = body.data.map((s: any) => s.shiftId);
      expect(shiftIds).not.toContain(PB_SHIFT_ID);
    });

    it('Physician B sees only own shifts in list', async () => {
      const res = await physicianBRequest('GET', '/api/v1/shifts');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBeGreaterThan(0);
      for (const shift of body.data) {
        expect(shift.providerId).toBe(PB_PROVIDER_ID);
      }
      const shiftIds = body.data.map((s: any) => s.shiftId);
      expect(shiftIds).not.toContain(PA_SHIFT_ID);
    });
  });

  // =========================================================================
  // 6. Favourite Isolation — List
  // =========================================================================

  describe('Favourite isolation — list', () => {
    it('Physician A sees only own favourites', async () => {
      const res = await physicianARequest('GET', '/api/v1/favourites');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBe(2);
      for (const fav of body.data) {
        expect(fav.providerId).toBe(PA_PROVIDER_ID);
      }
      const favIds = body.data.map((f: any) => f.favouriteId);
      expect(favIds).not.toContain(PB_FAVOURITE_ID_1);
      expect(favIds).not.toContain(PB_FAVOURITE_ID_2);
    });

    it('Physician B sees only own favourites', async () => {
      const res = await physicianBRequest('GET', '/api/v1/favourites');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.length).toBe(2);
      for (const fav of body.data) {
        expect(fav.providerId).toBe(PB_PROVIDER_ID);
      }
      const favIds = body.data.map((f: any) => f.favouriteId);
      expect(favIds).not.toContain(PA_FAVOURITE_ID_1);
      expect(favIds).not.toContain(PA_FAVOURITE_ID_2);
    });
  });

  // =========================================================================
  // 7. Favourite Isolation — Update
  // =========================================================================

  describe('Favourite isolation — update', () => {
    it('Physician B cannot update Physician A\'s favourite — returns 404 not 403', async () => {
      const res = await physicianBRequest(
        'PUT',
        `/api/v1/favourites/${PA_FAVOURITE_ID_1}`,
        { display_name: 'Hacked by B' },
      );
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
      // Verify favourite was NOT changed
      expect(favouritesStore[PA_FAVOURITE_ID_1].displayName).toBe('Office Visit');
    });

    it('Physician A cannot update Physician B\'s favourite — returns 404 not 403', async () => {
      const res = await physicianARequest(
        'PUT',
        `/api/v1/favourites/${PB_FAVOURITE_ID_1}`,
        { display_name: 'Hacked by A' },
      );
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
      expect(favouritesStore[PB_FAVOURITE_ID_1].displayName).toBe('ED Visit');
    });
  });

  // =========================================================================
  // 8. Favourite Isolation — Delete
  // =========================================================================

  describe('Favourite isolation — delete', () => {
    it('Physician B cannot delete Physician A\'s favourite — returns 404 not 403', async () => {
      const res = await physicianBRequest('DELETE', `/api/v1/favourites/${PA_FAVOURITE_ID_1}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
      // Verify favourite still exists
      expect(favouritesStore[PA_FAVOURITE_ID_1]).toBeDefined();
    });

    it('Physician A cannot delete Physician B\'s favourite — returns 404 not 403', async () => {
      const res = await physicianARequest('DELETE', `/api/v1/favourites/${PB_FAVOURITE_ID_1}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
      expect(favouritesStore[PB_FAVOURITE_ID_1]).toBeDefined();
    });
  });

  // =========================================================================
  // 9. Favourite Isolation — Reorder (batch validation)
  // =========================================================================

  describe('Favourite isolation — reorder', () => {
    it('Physician B cannot reorder Physician A\'s favourites — IDs rejected', async () => {
      const res = await physicianBRequest('PUT', '/api/v1/favourites/reorder', {
        items: [
          { favourite_id: PA_FAVOURITE_ID_1, sort_order: 2 },
          { favourite_id: PA_FAVOURITE_ID_2, sort_order: 1 },
        ],
      });
      // Should fail — IDs don't belong to Physician B
      expect([400, 404, 422, 500]).toContain(res.statusCode);
      expect(res.statusCode).not.toBe(200);
      // Verify sort order was NOT changed
      expect(favouritesStore[PA_FAVOURITE_ID_1].sortOrder).toBe(1);
      expect(favouritesStore[PA_FAVOURITE_ID_2].sortOrder).toBe(2);
    });

    it('Physician B cannot mix own and Physician A\'s favourite IDs in reorder', async () => {
      const res = await physicianBRequest('PUT', '/api/v1/favourites/reorder', {
        items: [
          { favourite_id: PB_FAVOURITE_ID_1, sort_order: 2 },
          { favourite_id: PA_FAVOURITE_ID_1, sort_order: 1 }, // Cross-tenant!
        ],
      });
      expect(res.statusCode).not.toBe(200);
      // Physician A's favourite sort order must not have changed
      expect(favouritesStore[PA_FAVOURITE_ID_1].sortOrder).toBe(1);
    });

    it('Physician A can reorder own favourites', async () => {
      const res = await physicianARequest('PUT', '/api/v1/favourites/reorder', {
        items: [
          { favourite_id: PA_FAVOURITE_ID_1, sort_order: 2 },
          { favourite_id: PA_FAVOURITE_ID_2, sort_order: 1 },
        ],
      });
      expect(res.statusCode).toBe(200);
    });
  });

  // =========================================================================
  // 10. Quick Claim Isolation — Cross-tenant Patient
  // =========================================================================

  describe('Quick claim isolation — cross-tenant patient', () => {
    it('Physician B cannot create quick claim for Physician A\'s patient — returns 404', async () => {
      const res = await physicianBRequest('POST', '/api/v1/mobile/quick-claim', {
        patient_id: PA_PATIENT_ID,
        health_service_code: '03.04A',
        date_of_service: '2026-02-19',
      });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
      const body = JSON.parse(res.body);
      expect(body.data).toBeUndefined();
    });

    it('Physician A cannot create quick claim for Physician B\'s patient — returns 404', async () => {
      const res = await physicianARequest('POST', '/api/v1/mobile/quick-claim', {
        patient_id: PB_PATIENT_ID,
        health_service_code: '03.04A',
        date_of_service: '2026-02-19',
      });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('Physician A can create quick claim for own patient', async () => {
      const res = await physicianARequest('POST', '/api/v1/mobile/quick-claim', {
        patient_id: PA_PATIENT_ID,
        health_service_code: '03.04A',
        date_of_service: '2026-02-19',
      });
      expect(res.statusCode).toBe(201);
      const body = JSON.parse(res.body);
      expect(body.data.claimId).toBeDefined();
    });
  });

  // =========================================================================
  // 11. Recent Patients Isolation
  // =========================================================================

  describe('Recent patients isolation', () => {
    it('Physician A\'s recent patients list contains only own patients', async () => {
      const res = await physicianARequest('GET', '/api/v1/mobile/recent-patients');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      for (const patient of body.data) {
        // Cross-reference against store to verify provider scoping
        const stored = Object.values(patientsStore).find(
          (p) => p.patientId === patient.patientId,
        );
        expect(stored?.providerId).toBe(PA_PROVIDER_ID);
      }
    });

    it('Physician B\'s recent patients list contains only own patients', async () => {
      const res = await physicianBRequest('GET', '/api/v1/mobile/recent-patients');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      for (const patient of body.data) {
        const stored = Object.values(patientsStore).find(
          (p) => p.patientId === patient.patientId,
        );
        expect(stored?.providerId).toBe(PB_PROVIDER_ID);
      }
    });

    it('Physician A\'s recent patients never contain Physician B\'s patients', async () => {
      const res = await physicianARequest('GET', '/api/v1/mobile/recent-patients');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const patientIds = body.data.map((p: any) => p.patientId);
      expect(patientIds).not.toContain(PB_PATIENT_ID);
    });
  });

  // =========================================================================
  // 12. Mobile Summary Isolation
  // =========================================================================

  describe('Mobile summary isolation', () => {
    it('Physician A\'s summary shows only own counts', async () => {
      const res = await physicianARequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      // Physician A has 1 claim in the store
      expect(body.data.todayClaimsCount).toBe(1);
      // Active shift should be Physician A's
      expect(body.data.activeShift).not.toBeNull();
      expect(body.data.activeShift.shiftId).toBe(PA_SHIFT_ID);
    });

    it('Physician B\'s summary shows only own counts', async () => {
      const res = await physicianBRequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      // Physician B has 1 claim in the store
      expect(body.data.todayClaimsCount).toBe(1);
      // Active shift should be Physician B's
      expect(body.data.activeShift).not.toBeNull();
      expect(body.data.activeShift.shiftId).toBe(PB_SHIFT_ID);
    });

    it('Physician A\'s summary does not include Physician B\'s active shift', async () => {
      const res = await physicianARequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      if (body.data.activeShift) {
        expect(body.data.activeShift.shiftId).not.toBe(PB_SHIFT_ID);
      }
    });

    it('Physician B with no active shift — summary shows null, not Physician A\'s shift', async () => {
      delete shiftsStore[PB_SHIFT_ID];
      const res = await physicianBRequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.data.activeShift).toBeNull();
    });
  });

  // =========================================================================
  // 13. Delegate Cross-Physician Isolation
  // =========================================================================

  describe('Delegate cross-physician isolation', () => {
    // Note: Shift routes are physician-only (delegates blocked by role check).
    // So delegate tests focus on favourites, mobile routes, and summary.

    it('Delegate of Physician A sees Physician A\'s favourites', async () => {
      const res = await delegateRequest('GET', '/api/v1/favourites');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      for (const fav of body.data) {
        expect(fav.providerId).toBe(PA_PROVIDER_ID);
      }
    });

    it('Delegate of Physician A sees Physician A\'s summary', async () => {
      const res = await delegateRequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      if (body.data.activeShift) {
        expect(body.data.activeShift.shiftId).toBe(PA_SHIFT_ID);
      }
    });

    it('Delegate of Physician A sees Physician A\'s recent patients', async () => {
      const res = await delegateRequest('GET', '/api/v1/mobile/recent-patients');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      for (const patient of body.data) {
        const stored = Object.values(patientsStore).find(
          (p) => p.patientId === patient.patientId,
        );
        expect(stored?.providerId).toBe(PA_PROVIDER_ID);
      }
    });

    it('Delegate of Physician A\'s recent patients never include Physician B\'s patients', async () => {
      const res = await delegateRequest('GET', '/api/v1/mobile/recent-patients');
      expect(res.statusCode).toBe(200);
      const body = JSON.parse(res.body);
      const patientIds = body.data.map((p: any) => p.patientId);
      expect(patientIds).not.toContain(PB_PATIENT_ID);
    });

    it('Delegate of Physician A cannot create quick claim for Physician B\'s patient', async () => {
      const res = await delegateRequest('POST', '/api/v1/mobile/quick-claim', {
        patient_id: PB_PATIENT_ID,
        health_service_code: '03.04A',
        date_of_service: '2026-02-19',
      });
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
    });

    it('Delegate of Physician A cannot update Physician B\'s favourite', async () => {
      const res = await delegateRequest(
        'PUT',
        `/api/v1/favourites/${PB_FAVOURITE_ID_1}`,
        { display_name: 'Hacked by delegate' },
      );
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
      expect(favouritesStore[PB_FAVOURITE_ID_1].displayName).toBe('ED Visit');
    });

    it('Delegate of Physician A cannot delete Physician B\'s favourite', async () => {
      const res = await delegateRequest('DELETE', `/api/v1/favourites/${PB_FAVOURITE_ID_1}`);
      expect(res.statusCode).toBe(404);
      expect(res.statusCode).not.toBe(403);
      expect(favouritesStore[PB_FAVOURITE_ID_1]).toBeDefined();
    });
  });

  // =========================================================================
  // 14. Cross-Physician Access Always Returns 404, NEVER 403
  // =========================================================================

  describe('Cross-physician access returns 404, never 403', () => {
    const crossTenantAttempts = [
      {
        description: 'shift summary',
        method: 'GET' as const,
        url: `/api/v1/shifts/${PA_SHIFT_ID}/summary`,
      },
      {
        description: 'end shift',
        method: 'POST' as const,
        url: `/api/v1/shifts/${PA_SHIFT_ID}/end`,
      },
      {
        description: 'log patient in shift',
        method: 'POST' as const,
        url: `/api/v1/shifts/${PA_SHIFT_ID}/patients`,
        payload: { patient_id: PA_PATIENT_ID, health_service_code: '03.04A', date_of_service: '2026-02-19' },
      },
      {
        description: 'update favourite',
        method: 'PUT' as const,
        url: `/api/v1/favourites/${PA_FAVOURITE_ID_1}`,
        payload: { display_name: 'Attack' },
      },
      {
        description: 'delete favourite',
        method: 'DELETE' as const,
        url: `/api/v1/favourites/${PA_FAVOURITE_ID_1}`,
      },
      {
        description: 'quick claim with cross-tenant patient',
        method: 'POST' as const,
        url: '/api/v1/mobile/quick-claim',
        payload: { patient_id: PA_PATIENT_ID, health_service_code: '03.04A', date_of_service: '2026-02-19' },
      },
    ];

    for (const attempt of crossTenantAttempts) {
      it(`${attempt.description} — Physician B accessing Physician A\'s resource returns 404`, async () => {
        const res = await physicianBRequest(attempt.method, attempt.url, attempt.payload);
        expect(res.statusCode).toBe(404);
        // Must NEVER be 403 (would confirm resource exists)
        expect(res.statusCode).not.toBe(403);
        const body = JSON.parse(res.body);
        expect(body.data).toBeUndefined();
        // Error response must not leak resource details
        expect(body.error.message).not.toContain(PA_SHIFT_ID);
        expect(body.error.message).not.toContain(PA_FAVOURITE_ID_1);
        expect(body.error.message).not.toContain(PA_PATIENT_ID);
      });
    }
  });

  // =========================================================================
  // 15. 404 Responses Reveal No Information
  // =========================================================================

  describe('404 responses reveal no information about the target resource', () => {
    it('shift 404 does not reveal shift details', async () => {
      const res = await physicianBRequest('GET', `/api/v1/shifts/${PA_SHIFT_ID}/summary`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.message).not.toContain('ACTIVE');
      expect(body.error.message).not.toContain(PA_LOCATION_ID);
      expect(body.error.message).not.toContain('patient');
      expect(body.error.message).not.toContain('150.00');
    });

    it('favourite 404 does not reveal favourite details', async () => {
      const res = await physicianBRequest('PUT', `/api/v1/favourites/${PA_FAVOURITE_ID_1}`, {
        display_name: 'Probe',
      });
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error.message).not.toContain('Office Visit');
      expect(body.error.message).not.toContain('03.04A');
      expect(body.error.message).not.toContain(PA_PROVIDER_ID);
    });

    it('404 response body has no data field', async () => {
      const res = await physicianBRequest('POST', `/api/v1/shifts/${PA_SHIFT_ID}/end`);
      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body).toHaveProperty('error');
      expect(body.data).toBeUndefined();
    });

    it('404 response does not contain internal identifiers', async () => {
      const res = await physicianBRequest('DELETE', `/api/v1/favourites/${PA_FAVOURITE_ID_1}`);
      expect(res.statusCode).toBe(404);
      const rawBody = res.body;
      expect(rawBody).not.toContain('postgres');
      expect(rawBody).not.toContain('drizzle');
      expect(rawBody).not.toContain('provider_id');
      expect(rawBody).not.toContain(PA_PROVIDER_ID);
      expect(rawBody).not.toContain(PB_PROVIDER_ID);
    });
  });

  // =========================================================================
  // 16. Bidirectional Isolation Verification
  // =========================================================================

  describe('Bidirectional isolation — both directions verified', () => {
    it('Physician A cannot access Physician B\'s shift summary', async () => {
      const res = await physicianARequest('GET', `/api/v1/shifts/${PB_SHIFT_ID}/summary`);
      expect(res.statusCode).toBe(404);
    });

    it('Physician B cannot access Physician A\'s shift summary', async () => {
      const res = await physicianBRequest('GET', `/api/v1/shifts/${PA_SHIFT_ID}/summary`);
      expect(res.statusCode).toBe(404);
    });

    it('Physician A cannot end Physician B\'s shift', async () => {
      const res = await physicianARequest('POST', `/api/v1/shifts/${PB_SHIFT_ID}/end`);
      expect(res.statusCode).toBe(404);
    });

    it('Physician B cannot end Physician A\'s shift', async () => {
      const res = await physicianBRequest('POST', `/api/v1/shifts/${PA_SHIFT_ID}/end`);
      expect(res.statusCode).toBe(404);
    });

    it('Physician A cannot update Physician B\'s favourite', async () => {
      const res = await physicianARequest('PUT', `/api/v1/favourites/${PB_FAVOURITE_ID_1}`, {
        display_name: 'Cross-tenant',
      });
      expect(res.statusCode).toBe(404);
    });

    it('Physician B cannot update Physician A\'s favourite', async () => {
      const res = await physicianBRequest('PUT', `/api/v1/favourites/${PA_FAVOURITE_ID_1}`, {
        display_name: 'Cross-tenant',
      });
      expect(res.statusCode).toBe(404);
    });

    it('Physician A cannot delete Physician B\'s favourite', async () => {
      const res = await physicianARequest('DELETE', `/api/v1/favourites/${PB_FAVOURITE_ID_1}`);
      expect(res.statusCode).toBe(404);
    });

    it('Physician B cannot delete Physician A\'s favourite', async () => {
      const res = await physicianBRequest('DELETE', `/api/v1/favourites/${PA_FAVOURITE_ID_1}`);
      expect(res.statusCode).toBe(404);
    });
  });
});
