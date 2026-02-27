/**
 * Fixture Factories
 *
 * Factory functions that insert real rows into the test DB.
 * Each returns the inserted row with all generated IDs.
 */
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import crypto from 'node:crypto';

import {
  users,
  type InsertUser,
  type SelectUser,
} from '@meritum/shared/schemas/db/iam.schema.js';

import {
  providers,
  type InsertProvider,
  type SelectProvider,
} from '@meritum/shared/schemas/db/provider.schema.js';

import {
  patients,
  type InsertPatient,
  type SelectPatient,
} from '@meritum/shared/schemas/db/patient.schema.js';

import {
  claims,
  type InsertClaim,
  type SelectClaim,
} from '@meritum/shared/schemas/db/claim.schema.js';

import {
  notifications,
  type InsertNotification,
  type SelectNotification,
} from '@meritum/shared/schemas/db/notification.schema.js';

import {
  referenceDataVersions,
  type InsertVersion,
  type SelectVersion,
} from '@meritum/shared/schemas/db/reference.schema.js';

/**
 * Create a test user.
 */
export async function createTestUser(
  db: NodePgDatabase,
  overrides: Partial<InsertUser> = {},
): Promise<SelectUser> {
  const data: InsertUser = {
    email: `user-${crypto.randomUUID()}@meritum.test`,
    passwordHash: '$argon2id$v=19$m=65536,t=3,p=4$salt$fakehashfortest',
    fullName: 'Test User',
    role: 'PHYSICIAN',
    ...overrides,
  };
  const [row] = await db.insert(users).values(data).returning();
  return row;
}

/**
 * Create a test provider (requires a user to already exist).
 * If no providerId is given, creates a user first.
 */
export async function createTestProvider(
  db: NodePgDatabase,
  overrides: Partial<InsertProvider> & { providerId?: string } = {},
): Promise<SelectProvider & { userId: string }> {
  let userId = overrides.providerId;
  if (!userId) {
    const user = await createTestUser(db);
    userId = user.userId;
  }

  const data: InsertProvider = {
    providerId: userId,
    billingNumber: overrides.billingNumber ?? `BN${crypto.randomBytes(4).toString('hex')}`,
    cpsaRegistrationNumber:
      overrides.cpsaRegistrationNumber ?? `CP${crypto.randomBytes(4).toString('hex')}`,
    firstName: overrides.firstName ?? 'Test',
    lastName: overrides.lastName ?? 'Provider',
    specialtyCode: overrides.specialtyCode ?? '00',
    physicianType: overrides.physicianType ?? 'GP',
    ...overrides,
    providerId: userId,
  };

  const [row] = await db.insert(providers).values(data).returning();
  return { ...row, userId };
}

/**
 * Create a test patient.
 */
export async function createTestPatient(
  db: NodePgDatabase,
  overrides: Partial<InsertPatient> & { providerId: string },
): Promise<SelectPatient> {
  const data: InsertPatient = {
    providerId: overrides.providerId,
    firstName: overrides.firstName ?? 'Jane',
    lastName: overrides.lastName ?? 'Doe',
    dateOfBirth: overrides.dateOfBirth ?? '1990-01-15',
    gender: overrides.gender ?? 'F',
    createdBy: overrides.createdBy ?? overrides.providerId,
    ...overrides,
  };
  const [row] = await db.insert(patients).values(data).returning();
  return row;
}

/**
 * Create a test claim (defaults to DRAFT state).
 */
export async function createTestClaim(
  db: NodePgDatabase,
  overrides: Partial<InsertClaim> & { physicianId: string; patientId: string },
): Promise<SelectClaim> {
  const data: InsertClaim = {
    physicianId: overrides.physicianId,
    patientId: overrides.patientId,
    claimType: overrides.claimType ?? 'AHCIP',
    dateOfService: overrides.dateOfService ?? '2026-01-15',
    importSource: overrides.importSource ?? 'MANUAL',
    ...overrides,
  };
  const [row] = await db.insert(claims).values(data).returning();
  return row;
}

/**
 * Create a test notification.
 */
export async function createTestNotification(
  db: NodePgDatabase,
  overrides: Partial<InsertNotification> & { recipientId: string },
): Promise<SelectNotification> {
  const data: InsertNotification = {
    recipientId: overrides.recipientId,
    eventType: overrides.eventType ?? 'CLAIM_VALIDATED',
    priority: overrides.priority ?? 'MEDIUM',
    title: overrides.title ?? 'Test Notification',
    body: overrides.body ?? 'Test notification body',
    ...overrides,
  };
  const [row] = await db.insert(notifications).values(data).returning();
  return row;
}

/**
 * Create a test reference data version.
 */
export async function createTestReferenceVersion(
  db: NodePgDatabase,
  overrides: Partial<InsertVersion> = {},
): Promise<SelectVersion> {
  const data: InsertVersion = {
    dataSet: overrides.dataSet ?? 'somb',
    versionLabel: overrides.versionLabel ?? `v-${crypto.randomBytes(3).toString('hex')}`,
    effectiveFrom: overrides.effectiveFrom ?? '2026-01-01',
    isActive: overrides.isActive ?? false,
    ...overrides,
  };
  const [row] = await db.insert(referenceDataVersions).values(data).returning();
  return row;
}
