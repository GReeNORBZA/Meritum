// ============================================================================
// Domain 10: Mobile Companion — PHI Leakage Prevention (Security)
//
// Verifies that PHI is never exposed through error responses, HTTP headers,
// application logs, or summary endpoints.
//
// Coverage:
//   - Error responses: 404/400/409/500 do not leak shift/patient/claim data
//   - Response headers: no X-Powered-By, no server version
//   - Audit logs: shift/claim logging captures IDs, not patient PHI
//   - Mobile summary: counts only, no patient names or claim details
//   - Recent patients: intentional PHI scoped to authenticated physician
//   - Shift summary: intentional PHI scoped to authenticated physician
//   - After-hours detection: boolean only, no patient data
//   - Quick note handling: never in AHCIP batch submission payloads
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
// Fixed test identities — Two isolated physicians
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

// ---------------------------------------------------------------------------
// Test data IDs — resources owned by each physician
// ---------------------------------------------------------------------------

// Physician A's resources
const PA_SHIFT_ID = 'aaaa0001-0000-0000-0000-000000000001';
const PA_FAVOURITE_ID = 'aaaa0002-0000-0000-0000-000000000001';
const PA_PATIENT_ID = 'aaaa0003-0000-0000-0000-000000000001';
const PA_CLAIM_ID = 'aaaa0004-0000-0000-0000-000000000001';
const PA_LOCATION_ID = 'aaaa0005-0000-0000-0000-000000000001';

// Physician B's resources
const PB_SHIFT_ID = 'bbbb0001-0000-0000-0000-000000000001';
const PB_FAVOURITE_ID = 'bbbb0002-0000-0000-0000-000000000001';
const PB_PATIENT_ID = 'bbbb0003-0000-0000-0000-000000000001';
const PB_LOCATION_ID = 'bbbb0005-0000-0000-0000-000000000001';

// Non-existent UUID
const NONEXISTENT_UUID = '99999999-9999-9999-9999-999999999999';

// Sensitive PHI data — must never leak in errors
const PA_PATIENT_NAME = 'Alice Smith';
const PA_PATIENT_PHN = '123456789';
const PA_PATIENT_DOB = '1980-01-15';
const PB_PATIENT_NAME = 'Charlie Brown';
const PB_PATIENT_PHN = '987654321';

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
  quickNote?: string;
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

  // --- Physician A's shift ---
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

  // --- Physician B's shift ---
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
  favouritesStore[PA_FAVOURITE_ID] = {
    favouriteId: PA_FAVOURITE_ID,
    providerId: PA_PROVIDER_ID,
    healthServiceCode: '03.04A',
    displayName: 'Office Visit',
    sortOrder: 1,
    defaultModifiers: null,
    createdAt: new Date(),
  };

  // --- Physician B's favourites ---
  favouritesStore[PB_FAVOURITE_ID] = {
    favouriteId: PB_FAVOURITE_ID,
    providerId: PB_PROVIDER_ID,
    healthServiceCode: '08.19A',
    displayName: 'ED Visit',
    sortOrder: 1,
    defaultModifiers: null,
    createdAt: new Date(),
  };

  // --- Physician A's patients ---
  patientsStore[PA_PATIENT_ID] = {
    patientId: PA_PATIENT_ID,
    providerId: PA_PROVIDER_ID,
    firstName: 'Alice',
    lastName: 'Smith',
    phn: PA_PATIENT_PHN,
    dateOfBirth: PA_PATIENT_DOB,
    gender: 'F',
  };

  // --- Physician B's patients ---
  patientsStore[PB_PATIENT_ID] = {
    patientId: PB_PATIENT_ID,
    providerId: PB_PROVIDER_ID,
    firstName: 'Charlie',
    lastName: 'Brown',
    phn: PB_PATIENT_PHN,
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
    quickNote: 'Patient complained of chest pain — DO NOT LEAK',
  };
}

// ---------------------------------------------------------------------------
// Mock repositories (provider-scoped)
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

// ---------------------------------------------------------------------------
// Provider-scoped mock shift repo
// ---------------------------------------------------------------------------

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
      const shiftClaims = Object.values(claimsStore)
        .filter((c) => c.providerId === providerId)
        .map((c) => {
          const patient = patientsStore[c.patientId];
          return {
            claimId: c.claimId,
            patientFirstName: patient?.firstName ?? 'Unknown',
            patientLastName: patient?.lastName ?? 'Unknown',
            healthServiceCode: c.healthServiceCode,
            fee: null,
          };
        });
      return {
        shiftId: shift.shiftId,
        providerId: shift.providerId,
        locationId: shift.locationId,
        shiftStart: shift.shiftStart,
        shiftEnd: shift.shiftEnd,
        status: shift.status,
        patientCount: shift.patientCount,
        estimatedValue: shift.estimatedValue,
        claims: shiftClaims,
      };
    }),

    list: vi.fn(async (providerId: string, _filters?: any) => {
      const data = Object.values(shiftsStore).filter(
        (s) => s.providerId === providerId,
      );
      return { data, total: data.length };
    }),

    incrementPatientCount: vi.fn(async (shiftId: string, providerId: string, _feeAmount: string) => {
      const shift = shiftsStore[shiftId];
      if (!shift || shift.providerId !== providerId) return null;
      shift.patientCount += 1;
      return shift;
    }),
  };
}

// ---------------------------------------------------------------------------
// Provider-scoped mock favourite repo
// ---------------------------------------------------------------------------

function createScopedFavouriteRepo() {
  return {
    create: vi.fn(async (data: any) => {
      // Check for duplicates (for 409 test)
      const existing = Object.values(favouritesStore).find(
        (f) => f.providerId === data.providerId && f.healthServiceCode === data.healthServiceCode,
      );
      if (existing) {
        const err: any = new Error('Favourite code already exists');
        err.statusCode = 409;
        err.code = 'CONFLICT';
        throw err;
      }
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
      for (const item of items) {
        const fav = favouritesStore[item.favourite_id];
        if (!fav || fav.providerId !== providerId) {
          throw new Error('Favourite not found');
        }
      }
      for (const item of items) {
        const fav = favouritesStore[item.favourite_id];
        if (fav) fav.sortOrder = item.sort_order;
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

// ---------------------------------------------------------------------------
// Provider-scoped mock claim repo
// ---------------------------------------------------------------------------

function createScopedClaimRepo() {
  return {
    createDraftClaim: vi.fn(async (providerId: string, data: any) => {
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
  };
}

// ---------------------------------------------------------------------------
// Build test dependencies
// ---------------------------------------------------------------------------

let shiftRepo: ReturnType<typeof createScopedShiftRepo>;
let favouriteRepo: ReturnType<typeof createScopedFavouriteRepo>;
let claimRepo: ReturnType<typeof createScopedClaimRepo>;

function createShiftDeps(): ShiftRouteDeps {
  return {
    serviceDeps: {
      repo: shiftRepo,
      locationCheck: {
        belongsToPhysician: vi.fn(async (locationId: string, physicianId: string) => {
          if (locationId === PA_LOCATION_ID && physicianId === PA_PROVIDER_ID) return true;
          if (locationId === PB_LOCATION_ID && physicianId === PB_PROVIDER_ID) return true;
          return false;
        }),
      },
      claimCreator: {
        createClaimFromShift: claimRepo.createClaimFromShift,
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
          // Check for duplicate PHN within this physician's patients
          const existing = Object.values(patientsStore).find(
            (p) => p.providerId === providerId && p.phn === data.phn,
          );
          if (existing) {
            const err: any = new Error('Patient with this PHN already exists');
            err.statusCode = 409;
            err.code = 'CONFLICT';
            throw err;
          }
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
        countPendingQueue: vi.fn(async (_physicianId: string) => 2),
      },
      unreadCounter: {
        countUnread: vi.fn(async (_recipientId: string) => 3),
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
    ipAddress: '127.0.0.2',
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
    events: { emit: vi.fn() },
  };

  shiftRepo = createScopedShiftRepo();
  favouriteRepo = createScopedFavouriteRepo();
  claimRepo = createScopedClaimRepo();

  const testApp = Fastify({ logger: false });
  testApp.setValidatorCompiler(validatorCompiler);
  testApp.setSerializerCompiler(serializerCompiler);

  await testApp.register(authPluginFp, { sessionDeps });

  testApp.setErrorHandler((error, _request, reply) => {
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

  await testApp.register(shiftRoutes, { deps: createShiftDeps() });
  await testApp.register(favouriteRoutes, { deps: createFavouriteDeps() });
  await testApp.register(mobileRoutes, { deps: createMobileDeps() });

  await testApp.ready();
  return testApp;
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function physicianARequest(
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  url: string,
  payload?: unknown,
) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${PA_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function physicianBRequest(
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  url: string,
  payload?: unknown,
) {
  return app.inject({
    method,
    url,
    headers: { cookie: `session=${PB_SESSION_TOKEN}` },
    ...(payload !== undefined ? { payload } : {}),
  });
}

function unauthenticated(
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  url: string,
  payload?: unknown,
) {
  return app.inject({
    method,
    url,
    ...(payload !== undefined ? { payload } : {}),
  });
}

// ---------------------------------------------------------------------------
// Utility: recursive key checker
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
// Test Suite
// ---------------------------------------------------------------------------

describe('Mobile PHI Leakage Prevention (Security)', () => {
  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    seedUsers();
    seedTestData();
    auditEntries = [];
    resetAuditRateLimiter();
  });

  // =========================================================================
  // 1. Error Response Sanitisation — PHI not in error responses
  // =========================================================================

  describe('Error responses do not contain PHI', () => {
    it('404 on shift access does not contain shift data or patient data', async () => {
      const res = await physicianARequest('GET', `/api/v1/shifts/${NONEXISTENT_UUID}/summary`);
      expect(res.statusCode).toBe(404);

      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();

      // No shift details
      expect(res.body).not.toContain('patientCount');
      expect(res.body).not.toContain('estimatedValue');
      expect(res.body).not.toContain('shiftStart');
      // No patient data
      expect(res.body).not.toContain('Alice');
      expect(res.body).not.toContain('Smith');
      expect(res.body).not.toContain(PA_PATIENT_PHN);
    });

    it('404 on cross-tenant shift does not reveal shift exists', async () => {
      // Physician A tries to access Physician B's shift
      const crossRes = await physicianARequest('GET', `/api/v1/shifts/${PB_SHIFT_ID}/summary`);
      const missingRes = await physicianARequest('GET', `/api/v1/shifts/${NONEXISTENT_UUID}/summary`);

      expect(crossRes.statusCode).toBe(404);
      expect(missingRes.statusCode).toBe(404);

      // Identical error shape — cannot distinguish cross-tenant from missing
      const crossBody = JSON.parse(crossRes.body);
      const missingBody = JSON.parse(missingRes.body);
      expect(crossBody.error.code).toBe(missingBody.error.code);
      expect(crossBody.error.message).toBe(missingBody.error.message);

      // No PB data leaked
      expect(crossRes.body).not.toContain(PB_PROVIDER_ID);
      expect(crossRes.body).not.toContain(PB_SHIFT_ID);
      expect(crossRes.body).not.toContain(PB_PATIENT_NAME);
    });

    it('400 on invalid input returns validation error only, no claim/patient data', async () => {
      const res = await physicianARequest('POST', '/api/v1/mobile/quick-claim', {
        patient_id: 'not-a-uuid',
        health_service_code: '',
        date_of_service: 'invalid-date',
      });

      expect(res.statusCode).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();

      // No patient or claim data
      expect(res.body).not.toContain('Alice');
      expect(res.body).not.toContain(PA_PATIENT_PHN);
      expect(res.body).not.toContain(PA_CLAIM_ID);
    });

    it('500 error returns generic message, no stack trace, no PHI', async () => {
      // Attempt an operation that triggers the generic error handler
      const res = await physicianARequest('PUT', `/api/v1/shifts/${NONEXISTENT_UUID}`, {});

      // May be 404 or 400 depending on routing — either way verify safety
      const body = JSON.parse(res.body);
      expect(body.error).not.toHaveProperty('stack');
      expect(body.error).not.toHaveProperty('stackTrace');
      expect(JSON.stringify(body)).not.toMatch(/at\s+\w+\s+\(/); // stack trace pattern
      expect(JSON.stringify(body)).not.toMatch(/\.ts:\d+:\d+/); // file:line:col
      expect(JSON.stringify(body)).not.toContain('node_modules');
      expect(JSON.stringify(body).toLowerCase()).not.toMatch(/postgres|drizzle|pg_catalog|sql/);
    });

    it('409 on duplicate active shift does not reveal existing shift details', async () => {
      // Physician A already has an active shift — try to start another
      const res = await physicianARequest('POST', '/api/v1/shifts', {
        location_id: PA_LOCATION_ID,
      });

      expect(res.statusCode).toBe(409);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();

      // Must NOT reveal the existing shift's ID, location, times
      expect(res.body).not.toContain(PA_SHIFT_ID);
      expect(res.body).not.toContain(PA_LOCATION_ID);
      expect(res.body).not.toContain('08:00:00');
      expect(res.body).not.toContain('patientCount');
      expect(res.body).not.toContain('estimatedValue');
      expect(res.body).not.toContain('150.00');
    });

    it('409 on duplicate favourite does not reveal details of existing favourite', async () => {
      // Try to add a favourite with a code that already exists
      const res = await physicianARequest('POST', '/api/v1/favourites', {
        health_service_code: '03.04A', // already exists for PA
        display_name: 'Duplicate',
        sort_order: 2,
      });

      expect(res.statusCode).toBe(409);
      const body = JSON.parse(res.body);
      expect(body.error).toBeDefined();
      expect(body.data).toBeUndefined();

      // Must not reveal the existing favourite's ID, display name, or sort order
      expect(res.body).not.toContain(PA_FAVOURITE_ID);
      expect(res.body).not.toContain('Office Visit');
    });

    it('401 response body contains only error object, no mobile data', async () => {
      const res = await unauthenticated('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).toBe(401);

      const body = JSON.parse(res.body);
      expect(Object.keys(body)).toEqual(['error']);
      expect(body.data).toBeUndefined();

      // No mobile data
      expect(res.body).not.toContain('todayClaimsCount');
      expect(res.body).not.toContain('pendingQueueCount');
      expect(res.body).not.toContain('activeShift');
      expect(res.body).not.toContain('shift');
      expect(res.body).not.toContain('favourite');
      expect(res.body).not.toContain('patient');
    });
  });

  // =========================================================================
  // 2. Response Header Security
  // =========================================================================

  describe('Response headers do not leak server internals', () => {
    it('no X-Powered-By header in authenticated responses', async () => {
      const res = await physicianARequest('GET', '/api/v1/shifts/active');
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in 401 responses', async () => {
      const res = await unauthenticated('GET', '/api/v1/shifts/active');
      expect(res.statusCode).toBe(401);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in 400 responses', async () => {
      const res = await physicianARequest('POST', '/api/v1/mobile/quick-claim', {
        invalid: true,
      });
      expect(res.statusCode).toBe(400);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no X-Powered-By header in 404 responses', async () => {
      const res = await physicianARequest('GET', `/api/v1/shifts/${NONEXISTENT_UUID}/summary`);
      expect(res.statusCode).toBe(404);
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('no Server header revealing version/technology', async () => {
      const res = await physicianARequest('GET', '/api/v1/shifts/active');
      const serverHeader = res.headers['server'];
      if (serverHeader) {
        const lower = (serverHeader as string).toLowerCase();
        expect(lower).not.toContain('fastify');
        expect(lower).not.toContain('node');
        expect(lower).not.toContain('express');
      }
    });

    it('no PHI in response headers', async () => {
      const res = await physicianARequest('GET', '/api/v1/mobile/summary');
      const headerStr = JSON.stringify(res.headers);

      expect(headerStr).not.toContain(PA_PATIENT_PHN);
      expect(headerStr).not.toContain('Alice');
      expect(headerStr).not.toContain('Smith');
      expect(headerStr).not.toContain(PA_PATIENT_ID);
    });

    it('authenticated responses include Content-Type: application/json', async () => {
      const res = await physicianARequest('GET', '/api/v1/mobile/summary');
      expect(res.headers['content-type']).toContain('application/json');
    });

    it('error responses include Content-Type: application/json', async () => {
      const res = await unauthenticated('GET', '/api/v1/mobile/summary');
      expect(res.headers['content-type']).toContain('application/json');
    });
  });

  // =========================================================================
  // 3. Audit Log Masking — IDs logged, not PHI
  // =========================================================================

  describe('Audit logs capture IDs, not PHI', () => {
    it('shift start audit log captures shift_id and provider_id, not patient names', async () => {
      // Start a new shift (PA already has one, so end it first)
      const endRes = await physicianARequest('POST', `/api/v1/shifts/${PA_SHIFT_ID}/end`);
      expect(endRes.statusCode).toBe(200);

      // Clear audit entries from end-shift and start fresh
      auditEntries = [];

      const newLocationId = PA_LOCATION_ID;
      const startRes = await physicianARequest('POST', '/api/v1/shifts', {
        location_id: newLocationId,
      });
      expect(startRes.statusCode).toBe(201);

      // Find shift.started audit entries
      const shiftAudits = auditEntries.filter(
        (e) => e.action === 'mobile.shift_started',
      );
      expect(shiftAudits.length).toBeGreaterThan(0);

      const auditString = JSON.stringify(shiftAudits);
      // Should contain IDs
      expect(auditString).toContain('locationId');
      // Should NOT contain patient names or PHN
      expect(auditString).not.toContain('Alice');
      expect(auditString).not.toContain('Smith');
      expect(auditString).not.toContain(PA_PATIENT_PHN);
      expect(auditString).not.toContain(PB_PATIENT_PHN);
    });

    it('quick claim audit log captures claim_id but not patient names/PHN', async () => {
      const res = await physicianARequest('POST', '/api/v1/mobile/quick-claim', {
        patient_id: PA_PATIENT_ID,
        health_service_code: '03.04A',
        date_of_service: '2026-02-19',
      });
      expect(res.statusCode).toBe(201);

      const claimAudits = auditEntries.filter(
        (e) => e.action === 'mobile.quick_claim_created',
      );
      expect(claimAudits.length).toBeGreaterThan(0);

      const auditString = JSON.stringify(claimAudits);
      // Should capture relevant IDs
      expect(auditString).toContain('patientId');
      expect(auditString).toContain('healthServiceCode');
      // Should NOT contain actual patient PHI
      expect(auditString).not.toContain('Alice');
      expect(auditString).not.toContain('Smith');
      expect(auditString).not.toContain(PA_PATIENT_PHN);
      expect(auditString).not.toContain(PA_PATIENT_DOB);
    });

    it('summary view audit log does not contain patient data', async () => {
      const res = await physicianARequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).toBe(200);

      const summaryAudits = auditEntries.filter(
        (e) => e.action === 'mobile.summary_viewed',
      );
      expect(summaryAudits.length).toBeGreaterThan(0);

      const auditString = JSON.stringify(summaryAudits);
      // Should contain aggregate counts, not PHI
      expect(auditString).toContain('todayClaimsCount');
      expect(auditString).not.toContain('Alice');
      expect(auditString).not.toContain('Smith');
      expect(auditString).not.toContain(PA_PATIENT_PHN);
      expect(auditString).not.toContain('Charlie');
      expect(auditString).not.toContain('Brown');
    });

    it('error logs contain generic error type, not PHI', async () => {
      // Trigger a 404 error — the error handler should not log PHI
      const res = await physicianARequest('GET', `/api/v1/shifts/${NONEXISTENT_UUID}/summary`);
      expect(res.statusCode).toBe(404);

      const body = JSON.parse(res.body);
      expect(body.error.message).not.toContain(PA_PATIENT_PHN);
      expect(body.error.message).not.toContain('Alice');
      expect(body.error.message).not.toContain('Smith');
      expect(body.error.message).not.toContain(NONEXISTENT_UUID);
    });
  });

  // =========================================================================
  // 4. Mobile Summary — Counts Only, No PHI
  // =========================================================================

  describe('Mobile summary is PHI-free (counts only)', () => {
    it('GET /mobile/summary returns counts only, no patient names', async () => {
      const res = await physicianARequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      const data = body.data;

      // Should contain numeric counts
      expect(typeof data.todayClaimsCount).toBe('number');
      expect(typeof data.pendingQueueCount).toBe('number');
      expect(typeof data.unreadNotificationsCount).toBe('number');

      // Should NOT contain patient names, PHN, or claim details
      const rawBody = res.body;
      expect(rawBody).not.toContain('Alice');
      expect(rawBody).not.toContain('Smith');
      expect(rawBody).not.toContain(PA_PATIENT_PHN);
      expect(rawBody).not.toContain('Charlie');
      expect(rawBody).not.toContain('Brown');
      expect(rawBody).not.toContain(PB_PATIENT_PHN);

      // Active shift summary should only have shiftId, shiftStart, patientCount, estimatedValue
      if (data.activeShift) {
        expect(data.activeShift).toHaveProperty('shiftId');
        expect(data.activeShift).toHaveProperty('patientCount');
        expect(data.activeShift).toHaveProperty('estimatedValue');
        // Should NOT have patient-level data
        expect(containsKeyRecursive(data.activeShift, 'patientName')).toBe(false);
        expect(containsKeyRecursive(data.activeShift, 'firstName')).toBe(false);
        expect(containsKeyRecursive(data.activeShift, 'lastName')).toBe(false);
        expect(containsKeyRecursive(data.activeShift, 'phn')).toBe(false);
        expect(containsKeyRecursive(data.activeShift, 'claims')).toBe(false);
      }
    });

    it('summary does not contain claim details', async () => {
      const res = await physicianARequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      // No claim-level detail
      expect(rawBody).not.toContain('healthServiceCode');
      expect(rawBody).not.toContain('dateOfService');
      expect(rawBody).not.toContain('03.04A');
      expect(rawBody).not.toContain('quickNote');
      expect(rawBody).not.toContain('chest pain');
    });

    it('summary does not leak other physician data', async () => {
      const res = await physicianARequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain(PB_PROVIDER_ID);
      expect(rawBody).not.toContain(PB_SHIFT_ID);
      expect(rawBody).not.toContain(PB_PATIENT_ID);
    });

    it('after-hours detection is boolean only, no patient data', async () => {
      // Log patient to a shift to get after-hours result
      const res = await physicianARequest(
        'POST',
        `/api/v1/shifts/${PA_SHIFT_ID}/patients`,
        {
          patient_id: PA_PATIENT_ID,
          health_service_code: '03.04A',
          date_of_service: '2026-02-19',
        },
      );
      expect(res.statusCode).toBe(201);

      const body = JSON.parse(res.body);
      const data = body.data;

      // After-hours result should be boolean/string only
      expect(typeof data.afterHoursEligible).toBe('boolean');
      // afterHoursModifier should be string or null
      expect(
        data.afterHoursModifier === null || typeof data.afterHoursModifier === 'string',
      ).toBe(true);

      // Response should NOT contain patient names or PHN
      const rawBody = res.body;
      expect(rawBody).not.toContain('Alice');
      expect(rawBody).not.toContain('Smith');
      expect(rawBody).not.toContain(PA_PATIENT_PHN);
    });
  });

  // =========================================================================
  // 5. Recent Patients — Intentional PHI Scoped to Authenticated Physician
  // =========================================================================

  describe('Recent patients response scoped to authenticated physician', () => {
    it('recent patients returns PHI only for the authenticated physician', async () => {
      const res = await physicianARequest('GET', '/api/v1/mobile/recent-patients');
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      const data = body.data;

      expect(Array.isArray(data)).toBe(true);
      expect(data.length).toBeGreaterThan(0);

      // All patients belong to PA
      for (const patient of data) {
        expect(patient).toHaveProperty('patientId');
        expect(patient).toHaveProperty('firstName');
        expect(patient).toHaveProperty('lastName');
        expect(patient).toHaveProperty('phn');
      }

      // Must NOT contain PB's patients
      const rawBody = res.body;
      expect(rawBody).not.toContain('Charlie');
      expect(rawBody).not.toContain('Brown');
      expect(rawBody).not.toContain(PB_PATIENT_PHN);
      expect(rawBody).not.toContain(PB_PATIENT_ID);
    });

    it('PB recent patients do not contain PA data', async () => {
      const res = await physicianBRequest('GET', '/api/v1/mobile/recent-patients');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('Alice');
      expect(rawBody).not.toContain('Smith');
      expect(rawBody).not.toContain(PA_PATIENT_PHN);
      expect(rawBody).not.toContain(PA_PATIENT_ID);
    });
  });

  // =========================================================================
  // 6. Shift Summary — Intentional PHI Scoped to Authenticated Physician
  // =========================================================================

  describe('Shift summary PHI scoped to authenticated physician', () => {
    it('shift summary includes patient names and HSC codes for own shift', async () => {
      const res = await physicianARequest('GET', `/api/v1/shifts/${PA_SHIFT_ID}/summary`);
      expect(res.statusCode).toBe(200);

      const body = JSON.parse(res.body);
      const data = body.data;

      // Summary is present with claims data (intentional PHI for own data)
      expect(data).toHaveProperty('shiftId');
      expect(data).toHaveProperty('claims');
      if (data.claims && data.claims.length > 0) {
        for (const claim of data.claims) {
          expect(claim).toHaveProperty('claimId');
          expect(claim).toHaveProperty('healthServiceCode');
        }
      }

      // Must NOT contain PB's data
      const rawBody = res.body;
      expect(rawBody).not.toContain(PB_PROVIDER_ID);
      expect(rawBody).not.toContain('Charlie');
      expect(rawBody).not.toContain('Brown');
      expect(rawBody).not.toContain(PB_PATIENT_PHN);
    });

    it('cross-tenant shift summary returns 404, not PB data', async () => {
      const res = await physicianARequest('GET', `/api/v1/shifts/${PB_SHIFT_ID}/summary`);
      expect(res.statusCode).toBe(404);

      expect(res.body).not.toContain(PB_PROVIDER_ID);
      expect(res.body).not.toContain('Charlie');
      expect(res.body).not.toContain(PB_PATIENT_PHN);
      expect(res.body).not.toContain('250.00'); // PB's estimatedValue
    });
  });

  // =========================================================================
  // 7. Quick Note Handling — Not in AHCIP Batch Submission
  // =========================================================================

  describe('Quick note is physician-private, not in submissions', () => {
    it('log patient response does not include quick_note', async () => {
      const res = await physicianARequest(
        'POST',
        `/api/v1/shifts/${PA_SHIFT_ID}/patients`,
        {
          patient_id: PA_PATIENT_ID,
          health_service_code: '03.04A',
          date_of_service: '2026-02-19',
          quick_note: 'Patient had chest pain, consider cardiac workup',
        },
      );
      expect(res.statusCode).toBe(201);

      const body = JSON.parse(res.body);
      // Response should only have claimId and afterHours info
      expect(body.data).toHaveProperty('claimId');
      expect(body.data).toHaveProperty('afterHoursEligible');

      // quick_note should NOT appear in the response
      expect(res.body).not.toContain('chest pain');
      expect(res.body).not.toContain('cardiac workup');
      expect(containsKeyRecursive(body, 'quickNote')).toBe(false);
      expect(containsKeyRecursive(body, 'quick_note')).toBe(false);
    });

    it('quick_note does not appear in audit log entries', async () => {
      await physicianARequest(
        'POST',
        `/api/v1/shifts/${PA_SHIFT_ID}/patients`,
        {
          patient_id: PA_PATIENT_ID,
          health_service_code: '03.04A',
          date_of_service: '2026-02-19',
          quick_note: 'Sensitive clinical observation - DO NOT LEAK',
        },
      );

      const auditString = JSON.stringify(auditEntries);
      expect(auditString).not.toContain('Sensitive clinical observation');
      expect(auditString).not.toContain('DO NOT LEAK');
      // Audit entries should not contain the quick_note key
      for (const entry of auditEntries) {
        if (entry.detail && typeof entry.detail === 'object') {
          expect(containsKeyRecursive(entry.detail, 'quickNote')).toBe(false);
          expect(containsKeyRecursive(entry.detail, 'quick_note')).toBe(false);
        }
      }
    });
  });

  // =========================================================================
  // 8. Sensitive Fields Not Leaked in Responses
  // =========================================================================

  describe('Sensitive fields never leak in any response', () => {
    it('mobile responses do not contain password_hash', async () => {
      const res = await physicianARequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).toBe(200);
      expect(res.body).not.toContain('passwordHash');
      expect(res.body).not.toContain('password_hash');
    });

    it('mobile responses do not contain session tokens', async () => {
      const res = await physicianARequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).toBe(200);
      expect(res.body).not.toContain('tokenHash');
      expect(res.body).not.toContain('token_hash');
      expect(res.body).not.toContain(PA_SESSION_TOKEN);
      expect(res.body).not.toContain(PA_SESSION_TOKEN_HASH);
    });

    it('mobile responses do not contain TOTP secrets', async () => {
      const res = await physicianARequest('GET', '/api/v1/mobile/summary');
      expect(res.statusCode).toBe(200);
      expect(res.body).not.toContain('totpSecret');
      expect(res.body).not.toContain('totp_secret');
      expect(res.body).not.toContain('JBSWY3DPEHPK3PXP');
    });

    it('shift list does not contain internal auth fields', async () => {
      const res = await physicianARequest('GET', '/api/v1/shifts');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('passwordHash');
      expect(rawBody).not.toContain('tokenHash');
      expect(rawBody).not.toContain('totpSecret');
      expect(rawBody).not.toContain(PA_SESSION_TOKEN);
    });

    it('favourites list does not contain internal auth fields', async () => {
      const res = await physicianARequest('GET', '/api/v1/favourites');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain('passwordHash');
      expect(rawBody).not.toContain('tokenHash');
      expect(rawBody).not.toContain('totpSecret');
      expect(rawBody).not.toContain(PA_SESSION_TOKEN);
    });
  });

  // =========================================================================
  // 9. Error Responses Are Generic — No Internal State Revealed
  // =========================================================================

  describe('Error responses do not reveal internal state', () => {
    it('all 404 responses have consistent error structure across shift endpoints', async () => {
      const routes = [
        { method: 'GET' as const, url: `/api/v1/shifts/${NONEXISTENT_UUID}/summary` },
        { method: 'POST' as const, url: `/api/v1/shifts/${NONEXISTENT_UUID}/end` },
        {
          method: 'POST' as const,
          url: `/api/v1/shifts/${NONEXISTENT_UUID}/patients`,
          payload: {
            patient_id: PA_PATIENT_ID,
            health_service_code: '03.04A',
            date_of_service: '2026-02-19',
          },
        },
      ];

      for (const route of routes) {
        const res = await physicianARequest(route.method, route.url, route.payload);

        if (res.statusCode === 404) {
          const body = JSON.parse(res.body);
          expect(body.error).toBeDefined();
          expect(body.data).toBeUndefined();
          expect(body.error).toHaveProperty('code');
          expect(body.error).toHaveProperty('message');
          // No stack traces
          expect(body.error).not.toHaveProperty('stack');
          expect(JSON.stringify(body)).not.toMatch(/\.ts:\d+/);
        }
      }
    });

    it('error responses never contain SQL-related keywords', async () => {
      const res = await physicianARequest('POST', '/api/v1/mobile/quick-claim', {
        patient_id: PA_PATIENT_ID,
        health_service_code: "'; DROP TABLE claims;--",
        date_of_service: '2026-02-19',
      });

      const lower = res.body.toLowerCase();
      expect(lower).not.toContain('postgres');
      expect(lower).not.toContain('drizzle');
      expect(lower).not.toContain('pg_catalog');
      expect(lower).not.toContain('syntax error');
    });

    it('error responses do not expose resource UUIDs in messages', async () => {
      const res = await physicianARequest('GET', `/api/v1/shifts/${NONEXISTENT_UUID}/summary`);
      expect(res.statusCode).toBe(404);

      const body = JSON.parse(res.body);
      expect(body.error.message).not.toContain(NONEXISTENT_UUID);
    });
  });

  // =========================================================================
  // 10. Cross-Tenant Leakage Prevention in All Endpoints
  // =========================================================================

  describe('Cross-tenant data never leaked', () => {
    it('shift list contains only authenticated physician shifts', async () => {
      const res = await physicianARequest('GET', '/api/v1/shifts');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain(PB_PROVIDER_ID);
      expect(rawBody).not.toContain(PB_SHIFT_ID);
      expect(rawBody).not.toContain(PB_LOCATION_ID);
    });

    it('favourites list contains only authenticated physician favourites', async () => {
      const res = await physicianARequest('GET', '/api/v1/favourites');
      expect(res.statusCode).toBe(200);

      const rawBody = res.body;
      expect(rawBody).not.toContain(PB_PROVIDER_ID);
      expect(rawBody).not.toContain(PB_FAVOURITE_ID);
      expect(rawBody).not.toContain('ED Visit'); // PB's favourite display name
      expect(rawBody).not.toContain('08.19A'); // PB's favourite code
    });

    it('cross-tenant shift end returns 404 without details', async () => {
      const res = await physicianARequest('POST', `/api/v1/shifts/${PB_SHIFT_ID}/end`);
      expect(res.statusCode).toBe(404);

      expect(res.body).not.toContain(PB_PROVIDER_ID);
      expect(res.body).not.toContain('250.00');
      expect(res.body).not.toContain('ACTIVE');
    });
  });
});
