#!/usr/bin/env tsx
// ============================================================================
// Meritum — Comprehensive Test Data Seed Script
// Populates all domains with realistic Alberta physician billing data.
// Idempotent: checks for existing seed user before inserting.
// Usage: cd apps/api && npx tsx src/seed.ts
// ============================================================================

import 'dotenv/config';
import { drizzle } from 'drizzle-orm/node-postgres';
import { eq } from 'drizzle-orm';
import * as pg from 'pg';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

// --- Schema Imports ---
import {
  users,
  auditLog,
} from '@meritum/shared/schemas/db/iam.schema.js';

import {
  providers,
  businessArrangements,
  practiceLocations,
  wcbConfigurations,
  delegateRelationships,
  submissionPreferences,
  hlinkConfigurations,
  pcpcmEnrolments,
} from '@meritum/shared/schemas/db/provider.schema.js';

import {
  patients,
} from '@meritum/shared/schemas/db/patient.schema.js';

import {
  claims,
  fieldMappingTemplates,
  shifts,
  claimTemplates,
  recentReferrers,
} from '@meritum/shared/schemas/db/claim.schema.js';

import {
  ahcipClaimDetails,
  ahcipBatches,
} from '@meritum/shared/schemas/db/ahcip.schema.js';

import {
  wcbClaimDetails,
  wcbInjuries,
  wcbInvoiceLines,
  wcbBatches,
} from '@meritum/shared/schemas/db/wcb.schema.js';

import {
  referenceDataVersions,
  hscCodes,
  diCodes,
  functionalCentres,
  modifierDefinitions,
  governingRules,
  explanatoryCodes,
  rrnpCommunities,
  hscModifierEligibility,
  bundlingRules,
} from '@meritum/shared/schemas/db/reference.schema.js';

import {
  aiRules,
  aiProviderLearning,
} from '@meritum/shared/schemas/db/intelligence.schema.js';

import {
  subscriptions,
  paymentHistory,
  statusComponents,
  referralCodes,
} from '@meritum/shared/schemas/db/platform.schema.js';

import {
  notifications,
  notificationPreferences,
} from '@meritum/shared/schemas/db/notification.schema.js';

import {
  onboardingProgress,
} from '@meritum/shared/schemas/db/onboarding.schema.js';

import {
  analyticsCache,
  reportSubscriptions,
} from '@meritum/shared/schemas/db/analytics.schema.js';

import {
  supportTickets,
  helpArticles,
} from '@meritum/shared/schemas/db/support.schema.js';

import {
  shiftSchedules,
  edShifts,
  favouriteCodes,
} from '@meritum/shared/schemas/db/mobile.schema.js';

// ============================================================================
// Helpers
// ============================================================================

/** Deterministic UUID from a seed string (v5-style via SHA-256 truncation) */
function seedUuid(label: string): string {
  const hash = crypto.createHash('sha256').update(`meritum-seed:${label}`).digest('hex');
  // Format as UUID v4 shape
  return [
    hash.slice(0, 8),
    hash.slice(8, 12),
    '4' + hash.slice(13, 16),
    ((parseInt(hash.slice(16, 17), 16) & 0x3) | 0x8).toString(16) + hash.slice(17, 20),
    hash.slice(20, 32),
  ].join('-');
}

/** Fake argon2 hash — not valid for auth but fills the column. Real logins won't work. */
const FAKE_PASSWORD_HASH = '$argon2id$v=19$m=65536,t=3,p=4$c2VlZC1kYXRh$' + 'A'.repeat(43);

/** Load scraped Fee Navigator JSON data */
function loadScrapedData<T>(filename: string): T {
  const scriptDir = path.dirname(new URL(import.meta.url).pathname);
  const dataDir = path.resolve(
    scriptDir,
    '../../..',
    'scripts/data/fee-navigator',
  );
  const filePath = path.join(dataDir, filename);
  if (!fs.existsSync(filePath)) {
    throw new Error(
      `Scraped data not found: ${filePath}. Run: npx tsx scripts/scrape-fee-navigator.ts`,
    );
  }
  return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
}

function daysAgo(n: number): Date {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d;
}

function dateStr(daysOffset: number): string {
  const d = new Date();
  d.setDate(d.getDate() + daysOffset);
  return d.toISOString().slice(0, 10);
}

function ts(daysOffset: number): Date {
  const d = new Date();
  d.setDate(d.getDate() + daysOffset);
  return d;
}

// ============================================================================
// Fixed IDs
// ============================================================================

// Physicians (user + provider share the same UUID)
const DR_CHEN_ID = seedUuid('dr-chen');
const DR_PATEL_ID = seedUuid('dr-patel');
const DR_OKAFOR_ID = seedUuid('dr-okafor');

// Delegate user
const DELEGATE_ID = seedUuid('delegate-sarah');

// Business Arrangements
const BA_CHEN_1 = seedUuid('ba-chen-1');
const BA_CHEN_2 = seedUuid('ba-chen-2');
const BA_PATEL_1 = seedUuid('ba-patel-1');
const BA_OKAFOR_1 = seedUuid('ba-okafor-1');

// Practice Locations
const LOC_CHEN_CLINIC = seedUuid('loc-chen-clinic');
const LOC_CHEN_HOSPITAL = seedUuid('loc-chen-hospital');
const LOC_PATEL_CLINIC = seedUuid('loc-patel-clinic');
const LOC_OKAFOR_ED = seedUuid('loc-okafor-ed');

// Patients (8 per physician = 24 total)
const patientIds = Array.from({ length: 24 }, (_, i) => seedUuid(`patient-${i}`));

// Claims (6 per physician = 18 total)
const claimIds = Array.from({ length: 18 }, (_, i) => seedUuid(`claim-${i}`));

// Reference data version
const REF_VERSION_ID = seedUuid('ref-version-somb-2026');
const RRNP_COMMUNITY_ID = seedUuid('rrnp-peace-river');

// Subscription
const SUB_CHEN = seedUuid('sub-chen');
const SUB_PATEL = seedUuid('sub-patel');
const SUB_OKAFOR = seedUuid('sub-okafor');

// ============================================================================
// Main seed function
// ============================================================================

async function main() {
  const pool = new pg.Pool({
    connectionString: process.env.DATABASE_URL ?? 'postgresql://meritum:8RhP39UFnAQwrv7H7r*NjB7d@localhost:5432/meritum',
  });
  const db = drizzle(pool);

  console.log('Checking for existing seed data...');
  const existing = await db.select({ userId: users.userId }).from(users).where(eq(users.userId, DR_CHEN_ID));
  if (existing.length > 0) {
    console.log('Seed data already exists (dr-chen found). Skipping.');
    await pool.end();
    return;
  }

  console.log('Seeding test data...\n');

  // ========================================================================
  // 1. IAM — Users
  // ========================================================================
  console.log('  [1/16] Users...');
  await db.insert(users).values([
    {
      userId: DR_CHEN_ID,
      email: 'dr.chen@meritum.test',
      passwordHash: FAKE_PASSWORD_HASH,
      fullName: 'Dr. Michelle Chen',
      phone: '780-555-0101',
      role: 'physician',
      emailVerified: true,
      mfaConfigured: false,
      subscriptionStatus: 'active',
      isActive: true,
    },
    {
      userId: DR_PATEL_ID,
      email: 'dr.patel@meritum.test',
      passwordHash: FAKE_PASSWORD_HASH,
      fullName: 'Dr. Raj Patel',
      phone: '403-555-0202',
      role: 'physician',
      emailVerified: true,
      mfaConfigured: true,
      subscriptionStatus: 'active',
      isActive: true,
    },
    {
      userId: DR_OKAFOR_ID,
      email: 'dr.okafor@meritum.test',
      passwordHash: FAKE_PASSWORD_HASH,
      fullName: 'Dr. Chioma Okafor',
      phone: '780-555-0303',
      role: 'physician',
      emailVerified: true,
      mfaConfigured: false,
      subscriptionStatus: 'trial',
      isActive: true,
    },
    {
      userId: DELEGATE_ID,
      email: 'sarah.delegate@meritum.test',
      passwordHash: FAKE_PASSWORD_HASH,
      fullName: 'Sarah Thompson',
      phone: '780-555-0404',
      role: 'delegate',
      emailVerified: true,
      mfaConfigured: false,
      subscriptionStatus: 'active',
      isActive: true,
    },
  ]);

  // ========================================================================
  // 2. Providers
  // ========================================================================
  console.log('  [2/16] Providers...');
  await db.insert(providers).values([
    {
      providerId: DR_CHEN_ID,
      billingNumber: '123456',
      cpsaRegistrationNumber: 'AB12345',
      firstName: 'Michelle',
      lastName: 'Chen',
      specialtyCode: '00',
      specialtyDescription: 'General Practice',
      physicianType: 'GP',
      status: 'ACTIVE',
      onboardingCompleted: true,
      isConnectCareUser: true,
    },
    {
      providerId: DR_PATEL_ID,
      billingNumber: '234567',
      cpsaRegistrationNumber: 'AB23456',
      firstName: 'Raj',
      lastName: 'Patel',
      specialtyCode: '08',
      specialtyDescription: 'Internal Medicine',
      physicianType: 'SPECIALIST',
      status: 'ACTIVE',
      onboardingCompleted: true,
      isConnectCareUser: false,
    },
    {
      providerId: DR_OKAFOR_ID,
      billingNumber: '345678',
      cpsaRegistrationNumber: 'AB34567',
      firstName: 'Chioma',
      lastName: 'Okafor',
      specialtyCode: '18',
      specialtyDescription: 'Emergency Medicine',
      physicianType: 'SPECIALIST',
      status: 'ACTIVE',
      onboardingCompleted: false,
      isConnectCareUser: false,
    },
  ]);

  // ========================================================================
  // 3. Business Arrangements
  // ========================================================================
  console.log('  [3/16] Business Arrangements & Locations...');
  await db.insert(businessArrangements).values([
    {
      baId: BA_CHEN_1,
      providerId: DR_CHEN_ID,
      baNumber: 'BA001',
      baType: 'INDEPENDENT',
      isPrimary: true,
      status: 'ACTIVE',
      effectiveDate: '2023-01-01',
    },
    {
      baId: BA_CHEN_2,
      providerId: DR_CHEN_ID,
      baNumber: 'BA002',
      baType: 'GROUP',
      isPrimary: false,
      status: 'ACTIVE',
      effectiveDate: '2024-06-01',
    },
    {
      baId: BA_PATEL_1,
      providerId: DR_PATEL_ID,
      baNumber: 'BA003',
      baType: 'INDEPENDENT',
      isPrimary: true,
      status: 'ACTIVE',
      effectiveDate: '2022-04-01',
    },
    {
      baId: BA_OKAFOR_1,
      providerId: DR_OKAFOR_ID,
      baNumber: 'BA004',
      baType: 'INDEPENDENT',
      isPrimary: true,
      status: 'ACTIVE',
      effectiveDate: '2025-01-15',
    },
  ]);

  // Practice Locations
  await db.insert(practiceLocations).values([
    {
      locationId: LOC_CHEN_CLINIC,
      providerId: DR_CHEN_ID,
      name: 'Westview Family Clinic',
      functionalCentre: 'OFFC',
      addressLine1: '1234 Jasper Ave NW',
      city: 'Edmonton',
      province: 'AB',
      postalCode: 'T5J 1S9',
      isDefault: true,
      isActive: true,
    },
    {
      locationId: LOC_CHEN_HOSPITAL,
      providerId: DR_CHEN_ID,
      name: 'Royal Alexandra Hospital',
      functionalCentre: 'HOSP',
      facilityNumber: 'RAH001',
      addressLine1: '10240 Kingsway NW',
      city: 'Edmonton',
      province: 'AB',
      postalCode: 'T5H 3V9',
      isDefault: false,
      isActive: true,
    },
    {
      locationId: LOC_PATEL_CLINIC,
      providerId: DR_PATEL_ID,
      name: 'South Calgary Medical',
      functionalCentre: 'OFFC',
      addressLine1: '7620 Elbow Dr SW',
      city: 'Calgary',
      province: 'AB',
      postalCode: 'T2V 1K2',
      isDefault: true,
      isActive: true,
    },
    {
      locationId: LOC_OKAFOR_ED,
      providerId: DR_OKAFOR_ID,
      name: 'University of Alberta Hospital ED',
      functionalCentre: 'EMER',
      facilityNumber: 'UAH001',
      addressLine1: '8440 112 St NW',
      city: 'Edmonton',
      province: 'AB',
      postalCode: 'T6G 2B7',
      isDefault: true,
      isActive: true,
    },
  ]);

  // WCB Configuration (for Dr. Okafor — ED physician)
  await db.insert(wcbConfigurations).values([
    {
      providerId: DR_OKAFOR_ID,
      contractId: 'WCB-9001',
      roleCode: 'TP',
      skillCode: '18',
      permittedFormTypes: ['C050E', 'C568A'],
      isDefault: true,
    },
  ]);

  // Delegate Relationship
  await db.insert(delegateRelationships).values([
    {
      physicianId: DR_CHEN_ID,
      delegateUserId: DELEGATE_ID,
      permissions: ['claims.view', 'claims.create', 'claims.edit', 'patients.view', 'patients.create'],
      status: 'ACTIVE',
      invitedAt: daysAgo(30),
      acceptedAt: daysAgo(29),
    },
  ]);

  // Submission Preferences
  await db.insert(submissionPreferences).values([
    {
      providerId: DR_CHEN_ID,
      ahcipSubmissionMode: 'AUTO_CLEAN',
      wcbSubmissionMode: 'REQUIRE_APPROVAL',
      batchReviewReminder: true,
      deadlineReminderDays: 7,
      updatedBy: DR_CHEN_ID,
    },
    {
      providerId: DR_PATEL_ID,
      ahcipSubmissionMode: 'MANUAL',
      wcbSubmissionMode: 'REQUIRE_APPROVAL',
      batchReviewReminder: true,
      deadlineReminderDays: 14,
      updatedBy: DR_PATEL_ID,
    },
  ]);

  // H-Link Configuration
  await db.insert(hlinkConfigurations).values([
    {
      providerId: DR_CHEN_ID,
      submitterPrefix: 'MC',
      credentialSecretRef: 'vault://hlink/dr-chen',
      accreditationStatus: 'ACCREDITED',
      accreditationDate: '2023-06-15',
    },
  ]);

  // ========================================================================
  // 4. Patients (8 per physician)
  // ========================================================================
  console.log('  [4/16] Patients...');

  const patientData = [
    // Dr. Chen's patients (indices 0-7)
    { idx: 0, providerId: DR_CHEN_ID, phn: '123456789', firstName: 'James', lastName: 'Morrison', dob: '1985-03-15', gender: 'M' },
    { idx: 1, providerId: DR_CHEN_ID, phn: '234567890', firstName: 'Emily', lastName: 'Watson', dob: '1972-11-22', gender: 'F' },
    { idx: 2, providerId: DR_CHEN_ID, phn: '345678901', firstName: 'Robert', lastName: 'Kim', dob: '1990-07-08', gender: 'M' },
    { idx: 3, providerId: DR_CHEN_ID, phn: '456789012', firstName: 'Sarah', lastName: 'Blackwood', dob: '1968-01-30', gender: 'F' },
    { idx: 4, providerId: DR_CHEN_ID, phn: '567890123', firstName: 'Michael', lastName: 'Rivera', dob: '2001-09-14', gender: 'M' },
    { idx: 5, providerId: DR_CHEN_ID, phn: '678901234', firstName: 'Jennifer', lastName: 'Oduya', dob: '1995-05-20', gender: 'F' },
    { idx: 6, providerId: DR_CHEN_ID, phn: '789012345', firstName: 'David', lastName: 'Makokis', dob: '1958-12-03', gender: 'M' },
    { idx: 7, providerId: DR_CHEN_ID, phn: '890123456', firstName: 'Linda', lastName: 'Tremblay', dob: '1980-04-17', gender: 'F' },
    // Dr. Patel's patients (indices 8-15)
    { idx: 8,  providerId: DR_PATEL_ID, phn: '901234567', firstName: 'Ahmed', lastName: 'Hassan', dob: '1975-06-25', gender: 'M' },
    { idx: 9,  providerId: DR_PATEL_ID, phn: '112345678', firstName: 'Maria', lastName: 'Santos', dob: '1988-02-11', gender: 'F' },
    { idx: 10, providerId: DR_PATEL_ID, phn: '223456789', firstName: 'Thomas', lastName: 'Olsen', dob: '1962-10-05', gender: 'M' },
    { idx: 11, providerId: DR_PATEL_ID, phn: '334567890', firstName: 'Susan', lastName: 'Campbell', dob: '1970-08-19', gender: 'F' },
    { idx: 12, providerId: DR_PATEL_ID, phn: '445678901', firstName: 'William', lastName: 'Fong', dob: '1955-03-28', gender: 'M' },
    { idx: 13, providerId: DR_PATEL_ID, phn: '556789012', firstName: 'Patricia', lastName: 'Dumont', dob: '1992-12-07', gender: 'F' },
    { idx: 14, providerId: DR_PATEL_ID, phn: '667890123', firstName: 'George', lastName: 'Lawson', dob: '1948-07-14', gender: 'M' },
    { idx: 15, providerId: DR_PATEL_ID, phn: '778901234', firstName: 'Karen', lastName: 'Brandt', dob: '1983-01-22', gender: 'F' },
    // Dr. Okafor's patients (indices 16-23)
    { idx: 16, providerId: DR_OKAFOR_ID, phn: '889012345', firstName: 'Daniel', lastName: 'White', dob: '1997-04-09', gender: 'M' },
    { idx: 17, providerId: DR_OKAFOR_ID, phn: '990123456', firstName: 'Nancy', lastName: 'Flett', dob: '1965-11-30', gender: 'F' },
    { idx: 18, providerId: DR_OKAFOR_ID, phn: '101234567', firstName: 'Christopher', lastName: 'Smyth', dob: '1978-08-23', gender: 'M' },
    { idx: 19, providerId: DR_OKAFOR_ID, phn: '212345678', firstName: 'Barbara', lastName: 'Fehr', dob: '1953-05-12', gender: 'F' },
    { idx: 20, providerId: DR_OKAFOR_ID, phn: '323456789', firstName: 'Jason', lastName: 'Leung', dob: '2003-02-06', gender: 'M' },
    { idx: 21, providerId: DR_OKAFOR_ID, phn: '434567890', firstName: 'Diane', lastName: 'Poirier', dob: '1987-09-18', gender: 'F' },
    { idx: 22, providerId: DR_OKAFOR_ID, phn: '545678901', firstName: 'Mark', lastName: 'Chickeness', dob: '1971-06-27', gender: 'M' },
    { idx: 23, providerId: DR_OKAFOR_ID, phn: '656789012', firstName: 'Carol', lastName: 'Redcrow', dob: '1960-03-04', gender: 'F' },
  ];

  await db.insert(patients).values(
    patientData.map(p => ({
      patientId: patientIds[p.idx],
      providerId: p.providerId,
      phn: p.phn,
      phnProvince: 'AB',
      firstName: p.firstName,
      lastName: p.lastName,
      dateOfBirth: p.dob,
      gender: p.gender,
      isActive: true,
      lastVisitDate: dateStr(-Math.floor(Math.random() * 30)),
      createdBy: p.providerId,
    }))
  );

  // ========================================================================
  // 5. Claims — AHCIP (12 claims) + WCB (6 claims)
  // ========================================================================
  console.log('  [5/16] Claims...');

  const hscExamples = ['03.03A', '03.04A', '03.05A', '03.08A', '08.19A', '08.19C', '13.99A', '03.03J', '03.04J', '03.05AA'];
  const diExamples = ['465', '250', '401', '780', '599', '724', '346', '272', '311', '428'];
  const states = ['DRAFT', 'VALIDATED', 'SUBMITTED', 'ASSESSED', 'PAID'] as const;

  // AHCIP claims for Dr. Chen (0-5)
  const ahcipClaimInserts = [];
  for (let i = 0; i < 6; i++) {
    ahcipClaimInserts.push({
      claimId: claimIds[i],
      physicianId: DR_CHEN_ID,
      patientId: patientIds[i],
      claimType: 'AHCIP',
      state: states[i % states.length],
      isClean: i % 3 !== 0 ? true : null,
      importSource: i < 3 ? 'MANUAL' : 'CONNECT_CARE',
      dateOfService: dateStr(-(i * 5 + 3)),
      submissionDeadline: dateStr(90 - i * 5),
      createdBy: i < 4 ? DR_CHEN_ID : DELEGATE_ID,
    });
  }

  // AHCIP claims for Dr. Patel (6-11)
  for (let i = 6; i < 12; i++) {
    ahcipClaimInserts.push({
      claimId: claimIds[i],
      physicianId: DR_PATEL_ID,
      patientId: patientIds[i + 2], // patients 8-13
      claimType: 'AHCIP',
      state: states[(i - 6) % states.length],
      isClean: true,
      importSource: 'MANUAL',
      dateOfService: dateStr(-(i * 3 + 1)),
      submissionDeadline: dateStr(90 - i * 3),
      createdBy: DR_PATEL_ID,
    });
  }

  // WCB claims for Dr. Okafor (12-17)
  for (let i = 12; i < 18; i++) {
    ahcipClaimInserts.push({
      claimId: claimIds[i],
      physicianId: DR_OKAFOR_ID,
      patientId: patientIds[i + 4], // patients 16-23
      claimType: i < 15 ? 'WCB' : 'AHCIP',
      state: states[(i - 12) % states.length],
      isClean: true,
      importSource: 'ED_SHIFT',
      dateOfService: dateStr(-(i - 11)),
      submissionDeadline: dateStr(90 - (i - 11)),
      createdBy: DR_OKAFOR_ID,
    });
  }

  await db.insert(claims).values(ahcipClaimInserts);

  // ========================================================================
  // 6. AHCIP Claim Details
  // ========================================================================
  console.log('  [6/16] AHCIP & WCB Details...');

  const ahcipDetailInserts = [];
  // AHCIP details for claims 0-11 and 15-17 (AHCIP type)
  const ahcipClaimIndices = [...Array.from({ length: 12 }, (_, i) => i), 15, 16, 17];
  for (const ci of ahcipClaimIndices) {
    ahcipDetailInserts.push({
      claimId: claimIds[ci],
      baNumber: ci < 6 ? 'BA001' : ci < 12 ? 'BA003' : 'BA004',
      functionalCentre: ci < 6 ? 'OFFC' : ci < 12 ? 'OFFC' : 'EMER',
      healthServiceCode: hscExamples[ci % hscExamples.length],
      diagnosticCode: diExamples[ci % diExamples.length],
      encounterType: ci >= 15 ? 'EMERGENCY' : 'OFFICE',
      calls: 1,
      submittedFee: ((ci + 1) * 35.5).toFixed(2),
    });
  }
  await db.insert(ahcipClaimDetails).values(ahcipDetailInserts);

  // WCB details for claims 12-14
  for (let i = 12; i < 15; i++) {
    await db.insert(wcbClaimDetails).values({
      claimId: claimIds[i],
      formId: 'C050E',
      submitterTxnId: `MER${String(i).padStart(12, '0')}`,
      reportCompletionDate: dateStr(-(i - 11)),
      practitionerBillingNumber: '345678',
      contractId: 'WCB-9001',
      roleCode: 'TP',
      practitionerFirstName: 'Chioma',
      practitionerLastName: 'Okafor',
      skillCode: '18',
      facilityType: 'H',
      patientNoPhnFlag: 'N',
      patientPhn: patientData[i + 4].phn,
      patientGender: patientData[i + 4].gender,
      patientFirstName: patientData[i + 4].firstName,
      patientLastName: patientData[i + 4].lastName,
      patientDob: patientData[i + 4].dob,
      patientAddressLine1: '123 Main St',
      patientCity: 'Edmonton',
      dateOfInjury: dateStr(-(i - 10)),
      createdBy: DR_OKAFOR_ID,
      updatedBy: DR_OKAFOR_ID,
    });

    // WCB injuries
    await db.insert(wcbInjuries).values({
      wcbClaimDetailId: (
        await db.select({ id: wcbClaimDetails.wcbClaimDetailId })
          .from(wcbClaimDetails)
          .where(eq(wcbClaimDetails.claimId, claimIds[i]))
      )[0].id,
      ordinal: 1,
      partOfBodyCode: 'WRIST',
      sideOfBodyCode: 'R',
      natureOfInjuryCode: 'SPRAIN',
    });
  }

  // ========================================================================
  // 7. AHCIP Batches
  // ========================================================================
  console.log('  [7/16] Batches...');
  await db.insert(ahcipBatches).values([
    {
      physicianId: DR_CHEN_ID,
      baNumber: 'BA001',
      batchWeek: dateStr(-14),
      status: 'SUBMITTED',
      claimCount: 3,
      totalSubmittedValue: '450.00',
      submittedAt: daysAgo(12),
      createdBy: DR_CHEN_ID,
    },
    {
      physicianId: DR_PATEL_ID,
      baNumber: 'BA003',
      batchWeek: dateStr(-7),
      status: 'ASSEMBLING',
      claimCount: 2,
      totalSubmittedValue: '320.00',
      createdBy: DR_PATEL_ID,
    },
  ]);

  // ========================================================================
  // 8. Reference Data (from scraped Fee Navigator data)
  // ========================================================================
  console.log('  [8/16] Reference Data (Fee Navigator)...');

  // Load scraped data
  interface ScrapedHsc {
    hscCode: string;
    description: string;
    baseFee: string | null;
    category: string | null;
    feeType: string;
    modifierEligibility: string[];
    surchargeEligible: boolean;
    notes: string | null;
    helpText: string | null;
    governingRuleReferences?: string[];
    requiresReferral?: boolean;
    selfReferralBlocked?: boolean;
    facilityDesignation?: 'in_office' | 'out_of_office' | null;
    specialtyRestrictions?: string[];
    bundlingExclusions?: Array<{
      excludedCode: string;
      relationship: 'not_claimable_with' | 'same_day_exclusion';
    }>;
    ageRestriction?: {
      text: string;
      minYears?: number;
      maxYears?: number;
      minMonths?: number;
      maxMonths?: number;
    } | null;
    maxPerDay?: number | null;
    maxPerVisit?: number | null;
    frequencyRestriction?: {
      text: string;
      count: number;
      period: string;
    } | null;
    requiresAnesthesia?: boolean;
  }
  interface ScrapedModifier {
    modifierCode: string;
    name: string;
    description: string;
    subCodes: Array<{ code: string; description: string }>;
  }
  interface ScrapedGoverningRule {
    ruleNumber: string;
    title: string;
    fullText: string;
    referencedHscCodes: string[];
  }
  interface ScrapedExplanatoryCode {
    code: string;
    description: string;
    category: string;
  }
  interface ScrapedHscModifier {
    hscCode: string;
    type: string;
    code: string;
    calls: string;
    explicit: string;
    action: string;
    amount: string;
  }

  const scrapedHsc = loadScrapedData<ScrapedHsc[]>('hsc-codes.json');
  const scrapedModifiers = loadScrapedData<ScrapedModifier[]>('modifiers.json');
  const scrapedRules = loadScrapedData<ScrapedGoverningRule[]>('governing-rules.json');
  const scrapedExplCodes = loadScrapedData<ScrapedExplanatoryCode[]>('explanatory-codes.json');
  const scrapedHscModifiers = loadScrapedData<ScrapedHscModifier[]>('hsc-modifiers.json');

  console.log(`    Loading ${scrapedHsc.length} HSC codes, ${scrapedModifiers.length} modifiers, ${scrapedRules.length} governing rules, ${scrapedExplCodes.length} explanatory codes, ${scrapedHscModifiers.length} HSC modifier eligibility rows`);

  // Version
  await db.insert(referenceDataVersions).values([
    {
      versionId: REF_VERSION_ID,
      dataSet: 'SOMB',
      versionLabel: 'SOMB 2025 Q1 - Fee Navigator',
      effectiveFrom: '2025-04-01',
      publishedBy: DR_CHEN_ID,
      publishedAt: daysAgo(60),
      isActive: true,
      recordsAdded: scrapedHsc.length,
      recordsModified: 0,
      recordsDeprecated: 0,
    },
  ]);

  // RRNP Community (not from Fee Navigator — kept as manual entry)
  await db.insert(rrnpCommunities).values([
    {
      communityId: RRNP_COMMUNITY_ID,
      communityName: 'Peace River',
      rrnpPercentage: '20.00',
      rrnpTier: 'TIER_2',
      region: 'Northern',
      versionId: REF_VERSION_ID,
      effectiveFrom: '2025-04-01',
    },
  ]);

  // HSC Codes — insert in batches of 500 to avoid query size limits
  const HSC_BATCH_SIZE = 500;
  for (let i = 0; i < scrapedHsc.length; i += HSC_BATCH_SIZE) {
    const batch = scrapedHsc.slice(i, i + HSC_BATCH_SIZE);
    await db.insert(hscCodes).values(
      batch.map((h) => ({
        hscCode: h.hscCode,
        description: h.description,
        baseFee: h.baseFee,
        feeType: h.feeType,
        modifierEligibility: h.modifierEligibility,
        surchargeEligible: h.surchargeEligible,
        governingRuleReferences: h.governingRuleReferences ?? [],
        requiresReferral: h.requiresReferral ?? false,
        selfReferralBlocked: h.selfReferralBlocked ?? false,
        specialtyRestrictions: h.specialtyRestrictions ?? [],
        maxPerDay: h.maxPerDay ?? null,
        maxPerVisit: h.maxPerVisit ?? null,
        ageRestriction: h.ageRestriction ?? null,
        frequencyRestriction: h.frequencyRestriction ?? null,
        requiresAnesthesia: h.requiresAnesthesia ?? false,
        facilityDesignation: h.facilityDesignation ?? null,
        notes: h.notes,
        helpText: h.helpText,
        versionId: REF_VERSION_ID,
        effectiveFrom: '2025-04-01',
      })),
    );
    if (i + HSC_BATCH_SIZE < scrapedHsc.length) {
      console.log(`    HSC codes: ${Math.min(i + HSC_BATCH_SIZE, scrapedHsc.length)}/${scrapedHsc.length}`);
    }
  }
  console.log(`    HSC codes: ${scrapedHsc.length}/${scrapedHsc.length} done`);

  // HSC Modifier Eligibility — insert 41k rows in batches of 500
  const MOD_ELIG_BATCH_SIZE = 500;
  for (let i = 0; i < scrapedHscModifiers.length; i += MOD_ELIG_BATCH_SIZE) {
    const batch = scrapedHscModifiers.slice(i, i + MOD_ELIG_BATCH_SIZE);
    await db.insert(hscModifierEligibility).values(
      batch.map((m) => ({
        hscCode: m.hscCode,
        modifierType: m.type,
        subCode: m.code,
        calls: m.calls || null,
        explicit: m.explicit === 'Yes',
        action: m.action,
        amount: m.amount,
        versionId: REF_VERSION_ID,
        effectiveFrom: '2025-04-01',
      })),
    );
    if (i + MOD_ELIG_BATCH_SIZE < scrapedHscModifiers.length) {
      console.log(`    HSC modifier eligibility: ${Math.min(i + MOD_ELIG_BATCH_SIZE, scrapedHscModifiers.length)}/${scrapedHscModifiers.length}`);
    }
  }
  console.log(`    HSC modifier eligibility: ${scrapedHscModifiers.length}/${scrapedHscModifiers.length} done`);

  // Build applicableHscFilter map from eligibility data
  const modifierHscMap = new Map<string, Set<string>>();
  for (const m of scrapedHscModifiers) {
    if (!modifierHscMap.has(m.type)) {
      modifierHscMap.set(m.type, new Set());
    }
    modifierHscMap.get(m.type)!.add(m.hscCode);
  }

  // DI Codes (10 common ones — not available from Fee Navigator)
  const diSeedData = [
    { code: '465', desc: 'Acute upper respiratory infection', cat: 'Respiratory' },
    { code: '250', desc: 'Diabetes mellitus', cat: 'Endocrine' },
    { code: '401', desc: 'Essential hypertension', cat: 'Circulatory' },
    { code: '780', desc: 'General symptoms', cat: 'Symptoms' },
    { code: '599', desc: 'Urinary tract disorder', cat: 'Genitourinary' },
    { code: '724', desc: 'Back disorders', cat: 'Musculoskeletal' },
    { code: '346', desc: 'Migraine', cat: 'Nervous' },
    { code: '272', desc: 'Disorders of lipoid metabolism', cat: 'Endocrine' },
    { code: '311', desc: 'Depression, not elsewhere classified', cat: 'Mental' },
    { code: '428', desc: 'Heart failure', cat: 'Circulatory' },
  ];

  await db.insert(diCodes).values(
    diSeedData.map(d => ({
      diCode: d.code,
      description: d.desc,
      category: d.cat,
      versionId: REF_VERSION_ID,
      effectiveFrom: '2025-04-01',
    }))
  );

  // Functional Centres (not from Fee Navigator — kept as manual entry)
  await db.insert(functionalCentres).values([
    { code: 'OFFC', name: 'Office / Clinic', facilityType: 'OFFICE', active: true, versionId: REF_VERSION_ID, effectiveFrom: '2025-04-01' },
    { code: 'HOSP', name: 'Hospital Inpatient', facilityType: 'HOSPITAL', active: true, versionId: REF_VERSION_ID, effectiveFrom: '2025-04-01' },
    { code: 'EMER', name: 'Emergency Department', facilityType: 'EMERGENCY', active: true, versionId: REF_VERSION_ID, effectiveFrom: '2025-04-01' },
    { code: 'LTCR', name: 'Long Term Care', facilityType: 'LTC', active: true, versionId: REF_VERSION_ID, effectiveFrom: '2025-04-01' },
  ]);

  // Modifier Definitions — all 42 from Fee Navigator (with applicableHscFilter)
  await db.insert(modifierDefinitions).values(
    scrapedModifiers.map((m) => {
      const hscSet = modifierHscMap.get(m.modifierCode);
      let applicableHscFilter: Record<string, unknown> = {};
      if (hscSet) {
        if (hscSet.size > 2500) {
          applicableHscFilter = { all: true };
        } else {
          applicableHscFilter = { codes: [...hscSet].sort() };
        }
      }
      return {
        modifierCode: m.modifierCode,
        name: m.name,
        description: m.description,
        type: 'MODIFIER',
        calculationMethod: 'VARIES',
        calculationParams: m.subCodes.length > 0 ? { subCodes: m.subCodes } : {},
        applicableHscFilter,
        versionId: REF_VERSION_ID,
        effectiveFrom: '2025-04-01',
      };
    }),
  );

  // Governing Rules — all 19 from Fee Navigator
  await db.insert(governingRules).values(
    scrapedRules.map((r) => ({
      ruleId: `GR-${r.ruleNumber}`,
      ruleName: r.title,
      ruleCategory: 'GENERAL',
      description: r.fullText,
      ruleLogic: { referencedHscCodes: r.referencedHscCodes },
      severity: 'ERROR',
      errorMessage: `Governing Rule ${r.ruleNumber} violation: ${r.title}`,
      sourceReference: `SOMB Governing Rule ${r.ruleNumber}`,
      sourceUrl: `https://apps.albertadoctors.org/fee-navigator/governing-rules/${r.ruleNumber}`,
      versionId: REF_VERSION_ID,
      effectiveFrom: '2025-04-01',
    })),
  );

  // Explanatory Codes — all 123 from Fee Navigator
  await db.insert(explanatoryCodes).values(
    scrapedExplCodes.map((e) => ({
      explCode: e.code,
      description: e.description,
      severity: 'INFO',
      versionId: REF_VERSION_ID,
      effectiveFrom: '2025-04-01',
    })),
  );

  // Bundling Rules — extracted from HSC notes text
  const bundlingPairs = new Map<string, { codeA: string; codeB: string; relationship: string; description: string }>();
  for (const h of scrapedHsc) {
    if (!h.bundlingExclusions?.length) continue;
    for (const excl of h.bundlingExclusions) {
      // Canonical ordering: codeA < codeB
      const [codeA, codeB] =
        h.hscCode < excl.excludedCode
          ? [h.hscCode, excl.excludedCode]
          : [excl.excludedCode, h.hscCode];
      const key = `${codeA}:${codeB}`;
      if (!bundlingPairs.has(key)) {
        const rel =
          excl.relationship === 'same_day_exclusion'
            ? 'SAME_DAY_EXCLUSION'
            : 'NOT_CLAIMABLE_WITH';
        bundlingPairs.set(key, {
          codeA,
          codeB,
          relationship: rel,
          description: `${h.hscCode} may not be claimed with ${excl.excludedCode}`,
        });
      }
    }
  }

  if (bundlingPairs.size > 0) {
    const bundlingRows = [...bundlingPairs.values()];
    const BUNDLING_BATCH_SIZE = 500;
    for (let i = 0; i < bundlingRows.length; i += BUNDLING_BATCH_SIZE) {
      const batch = bundlingRows.slice(i, i + BUNDLING_BATCH_SIZE);
      await db.insert(bundlingRules).values(
        batch.map((b) => ({
          codeA: b.codeA,
          codeB: b.codeB,
          relationship: b.relationship,
          description: b.description,
          sourceReference: 'SOMB Fee Navigator notes',
        })),
      );
    }
    console.log(`    Bundling rules: ${bundlingRows.length} pairs inserted`);
  }

  // ========================================================================
  // 9. Intelligence Engine
  // ========================================================================
  console.log('  [9/16] AI Rules...');

  const aiRule1Id = seedUuid('ai-rule-cmgp');
  const aiRule2Id = seedUuid('ai-rule-lscd');

  await db.insert(aiRules).values([
    {
      ruleId: aiRule1Id,
      name: 'Missing CMGP modifier',
      category: 'MODIFIER_SUGGESTION',
      claimType: 'AHCIP',
      conditions: {
        type: 'and',
        children: [
          { type: 'set_membership', field: 'claim.healthServiceCode', operator: 'IN', value: ['03.03A', '03.04A'] },
          { type: 'existence', field: 'claim.modifiers.CMGP', operator: 'IS NULL' },
        ],
      },
      suggestionTemplate: {
        title: 'Add CMGP modifier',
        description: 'Comprehensive care premium is eligible for this visit type.',
        revenue_impact_formula: 'ref.cmgp_value',
        source_reference: 'SOMB 2026 Section 3.2.1',
      },
      priorityFormula: '80',
      isActive: true,
    },
    {
      ruleId: aiRule2Id,
      name: 'After-hours surcharge eligible',
      category: 'SURCHARGE_SUGGESTION',
      claimType: 'AHCIP',
      conditions: {
        type: 'and',
        children: [
          { type: 'temporal', field: 'claim.dateOfService', operator: '>', value: '17:00' },
        ],
      },
      suggestionTemplate: {
        title: 'Apply LSCD surcharge',
        description: 'Service performed after hours qualifies for the LSCD modifier.',
        source_reference: 'SOMB 2026 Surcharges',
      },
      priorityFormula: '60',
      isActive: true,
    },
  ]);

  // Provider Learning
  await db.insert(aiProviderLearning).values([
    {
      providerId: DR_CHEN_ID,
      ruleId: aiRule1Id,
      timesShown: 12,
      timesAccepted: 10,
      timesDismissed: 2,
      consecutiveDismissals: 0,
      isSuppressed: false,
    },
  ]);

  // ========================================================================
  // 10. Platform — Subscriptions & Payments
  // ========================================================================
  console.log('  [10/16] Subscriptions...');

  await db.insert(subscriptions).values([
    {
      subscriptionId: SUB_CHEN,
      providerId: DR_CHEN_ID,
      stripeCustomerId: 'cus_test_chen',
      stripeSubscriptionId: 'sub_test_chen',
      plan: 'PHYSICIAN_MONTHLY',
      status: 'ACTIVE',
      currentPeriodStart: daysAgo(15),
      currentPeriodEnd: ts(15),
    },
    {
      subscriptionId: SUB_PATEL,
      providerId: DR_PATEL_ID,
      stripeCustomerId: 'cus_test_patel',
      stripeSubscriptionId: 'sub_test_patel',
      plan: 'PHYSICIAN_ANNUAL',
      status: 'ACTIVE',
      currentPeriodStart: daysAgo(120),
      currentPeriodEnd: ts(245),
    },
    {
      subscriptionId: SUB_OKAFOR,
      providerId: DR_OKAFOR_ID,
      stripeCustomerId: 'cus_test_okafor',
      stripeSubscriptionId: 'sub_test_okafor',
      plan: 'PHYSICIAN_MONTHLY',
      status: 'TRIAL',
      currentPeriodStart: daysAgo(5),
      currentPeriodEnd: ts(25),
      trialEnd: ts(25),
    },
  ]);

  // Payment History
  await db.insert(paymentHistory).values([
    {
      subscriptionId: SUB_CHEN,
      stripeInvoiceId: 'inv_test_chen_001',
      amountCad: '149.00',
      gstAmount: '7.45',
      totalCad: '156.45',
      status: 'PAID',
      paidAt: daysAgo(15),
    },
    {
      subscriptionId: SUB_PATEL,
      stripeInvoiceId: 'inv_test_patel_001',
      amountCad: '1490.00',
      gstAmount: '74.50',
      totalCad: '1564.50',
      status: 'PAID',
      paidAt: daysAgo(120),
    },
  ]);

  // Status Components
  await db.insert(statusComponents).values([
    { name: 'web_app', displayName: 'Web Application', status: 'operational', sortOrder: 0 },
    { name: 'api', displayName: 'API', status: 'operational', sortOrder: 1 },
    { name: 'hlink', displayName: 'H-Link Gateway', status: 'operational', sortOrder: 2 },
    { name: 'wcb_gateway', displayName: 'WCB Gateway', status: 'operational', sortOrder: 3 },
    { name: 'database', displayName: 'Database', status: 'operational', sortOrder: 4 },
    { name: 'notifications', displayName: 'Notifications', status: 'operational', sortOrder: 5 },
    { name: 'analytics', displayName: 'Analytics Engine', status: 'operational', sortOrder: 6 },
    { name: 'ai_engine', displayName: 'AI Coach Engine', status: 'operational', sortOrder: 7 },
  ]);

  // Referral Codes
  await db.insert(referralCodes).values([
    { referrerUserId: DR_CHEN_ID, code: 'CHEN2026', isActive: true },
    { referrerUserId: DR_PATEL_ID, code: 'PATEL2026', isActive: true },
  ]);

  // ========================================================================
  // 11. Notifications
  // ========================================================================
  console.log('  [11/16] Notifications...');

  await db.insert(notifications).values([
    {
      recipientId: DR_CHEN_ID,
      eventType: 'claim.assessed',
      priority: 'NORMAL',
      title: 'Claim assessed',
      body: 'Your claim for patient James Morrison on ' + dateStr(-8) + ' has been assessed.',
      actionUrl: '/claims/' + claimIds[3],
      channelsDelivered: { inApp: true, email: false },
    },
    {
      recipientId: DR_CHEN_ID,
      eventType: 'batch.submitted',
      priority: 'NORMAL',
      title: 'Batch submitted successfully',
      body: 'AHCIP batch for week of ' + dateStr(-14) + ' was submitted (3 claims, $450.00).',
      channelsDelivered: { inApp: true, email: true },
    },
    {
      recipientId: DR_CHEN_ID,
      eventType: 'claim.deadline_approaching',
      priority: 'URGENT',
      title: 'Submission deadline approaching',
      body: '2 claims have submission deadlines within the next 14 days.',
      channelsDelivered: { inApp: true, email: true },
    },
    {
      recipientId: DR_PATEL_ID,
      eventType: 'claim.paid',
      priority: 'NORMAL',
      title: 'Payment received',
      body: 'Payment of $196.30 received for claim assessed on ' + dateStr(-10) + '.',
      channelsDelivered: { inApp: true, email: false },
    },
    {
      recipientId: DR_OKAFOR_ID,
      eventType: 'onboarding.reminder',
      priority: 'NORMAL',
      title: 'Complete your onboarding',
      body: 'Finish setting up your account to start submitting claims.',
      actionUrl: '/onboarding',
      channelsDelivered: { inApp: true, email: true },
    },
  ]);

  // Notification Preferences
  await db.insert(notificationPreferences).values([
    { providerId: DR_CHEN_ID, eventCategory: 'claim', inAppEnabled: true, emailEnabled: true, digestMode: 'IMMEDIATE' },
    { providerId: DR_CHEN_ID, eventCategory: 'batch', inAppEnabled: true, emailEnabled: true, digestMode: 'DAILY' },
    { providerId: DR_CHEN_ID, eventCategory: 'billing', inAppEnabled: true, emailEnabled: false, digestMode: 'IMMEDIATE' },
    { providerId: DR_PATEL_ID, eventCategory: 'claim', inAppEnabled: true, emailEnabled: true, digestMode: 'IMMEDIATE' },
  ]);

  // ========================================================================
  // 12. Onboarding
  // ========================================================================
  console.log('  [12/16] Onboarding...');

  await db.insert(onboardingProgress).values([
    {
      userId: DR_CHEN_ID,
      stepsCompleted: ['profile', 'billing_number', 'business_arrangement', 'practice_location', 'hlink', 'first_claim'],
      currentStep: 'completed',
      completedAt: daysAgo(180),
    },
    {
      userId: DR_PATEL_ID,
      stepsCompleted: ['profile', 'billing_number', 'business_arrangement', 'practice_location', 'first_claim'],
      currentStep: 'completed',
      completedAt: daysAgo(90),
    },
    {
      userId: DR_OKAFOR_ID,
      stepsCompleted: ['profile', 'billing_number'],
      currentStep: 'business_arrangement',
    },
  ]);

  // ========================================================================
  // 13. Analytics
  // ========================================================================
  console.log('  [13/16] Analytics...');

  const analyticsPeriods = [
    { offset: -30, label: 'last-month' },
    { offset: 0, label: 'current-month' },
  ];

  for (const { offset, label } of analyticsPeriods) {
    await db.insert(analyticsCache).values([
      {
        providerId: DR_CHEN_ID,
        metricKey: 'revenue_monthly',
        periodStart: ts(offset),
        periodEnd: ts(offset + 30),
        dimensions: { specialty: '00' },
        value: { amount: offset === 0 ? 8450.75 : 7920.30, currency: 'CAD' },
      },
      {
        providerId: DR_CHEN_ID,
        metricKey: 'claims_submitted',
        periodStart: ts(offset),
        periodEnd: ts(offset + 30),
        dimensions: { claimType: 'AHCIP' },
        value: { count: offset === 0 ? 42 : 38 },
      },
      {
        providerId: DR_CHEN_ID,
        metricKey: 'rejection_rate',
        periodStart: ts(offset),
        periodEnd: ts(offset + 30),
        dimensions: {},
        value: { rate: offset === 0 ? 3.2 : 4.1 },
      },
    ]);
  }

  // Report Subscriptions
  await db.insert(reportSubscriptions).values([
    {
      providerId: DR_CHEN_ID,
      reportType: 'monthly_summary',
      frequency: 'MONTHLY',
      deliveryMethod: 'EMAIL',
      isActive: true,
    },
    {
      providerId: DR_PATEL_ID,
      reportType: 'monthly_summary',
      frequency: 'MONTHLY',
      deliveryMethod: 'EMAIL',
      isActive: true,
    },
  ]);

  // ========================================================================
  // 14. Support
  // ========================================================================
  console.log('  [14/16] Support & Help...');

  await db.insert(helpArticles).values([
    {
      slug: 'getting-started-overview',
      title: 'Getting Started with Meritum',
      category: 'getting-started',
      content: 'Welcome to Meritum! This guide walks you through setting up your account, adding your billing number, and submitting your first AHCIP claim.',
      summary: 'Complete guide to setting up your Meritum account and submitting your first claim.',
      isPublished: true,
      sortOrder: 0,
    },
    {
      slug: 'ahcip-claim-submission',
      title: 'How to Submit an AHCIP Claim',
      category: 'claims',
      content: 'Step-by-step guide for submitting AHCIP claims through Meritum, including selecting HSC codes, entering patient details, and batch submission.',
      summary: 'Learn how to create and submit AHCIP claims through the Meritum platform.',
      isPublished: true,
      sortOrder: 1,
    },
    {
      slug: 'wcb-electronic-reporting',
      title: 'WCB Electronic Injury Reporting',
      category: 'wcb',
      content: 'Guide to completing and submitting WCB forms (C050E, C151, C568A, C569, C570) electronically through Meritum.',
      summary: 'Complete guide to WCB electronic injury reporting forms and submission.',
      isPublished: true,
      sortOrder: 2,
    },
    {
      slug: 'understanding-explanatory-codes',
      title: 'Understanding AHCIP Explanatory Codes',
      category: 'claims',
      content: 'Reference guide for common AHCIP explanatory codes returned on assessed claims, including causes and suggested actions.',
      summary: 'Decode AHCIP explanatory codes and learn how to resolve claim issues.',
      isPublished: true,
      sortOrder: 3,
    },
    {
      slug: 'analytics-dashboard',
      title: 'Using the Analytics Dashboard',
      category: 'analytics',
      content: 'Learn how to read your revenue analytics, track claim performance, and generate reports.',
      summary: 'Guide to the Meritum analytics dashboard and reporting features.',
      isPublished: true,
      sortOrder: 4,
    },
    {
      slug: 'managing-subscriptions',
      title: 'Subscription Plans and Billing',
      category: 'billing',
      content: 'Information about Meritum subscription plans, billing cycles, payment methods, and how to change your plan.',
      summary: 'Everything you need to know about Meritum subscription plans and billing.',
      isPublished: true,
      sortOrder: 5,
    },
  ]);

  // Support Tickets
  await db.insert(supportTickets).values([
    {
      providerId: DR_CHEN_ID,
      subject: 'Claim batch stuck in ASSEMBLING status',
      description: 'My batch from last week has been in ASSEMBLING status for 3 days. It contains 5 claims that were all validated.',
      category: 'claims',
      priority: 'HIGH',
      status: 'OPEN',
    },
    {
      providerId: DR_PATEL_ID,
      subject: 'Question about CMGP modifier eligibility',
      description: 'I am an internist — can I bill the CMGP modifier for comprehensive assessments? The system is not suggesting it.',
      category: 'billing',
      priority: 'NORMAL',
      status: 'RESOLVED',
    },
  ]);

  // ========================================================================
  // 15. Mobile — Shifts, Schedules, Favourites
  // ========================================================================
  console.log('  [15/16] Mobile (shifts, favourites)...');

  // Shift Schedules
  const scheduleId = seedUuid('schedule-okafor-1');
  await db.insert(shiftSchedules).values([
    {
      scheduleId,
      providerId: DR_OKAFOR_ID,
      locationId: LOC_OKAFOR_ED,
      name: 'Regular ED Shift',
      rrule: 'FREQ=WEEKLY;BYDAY=MO,WE,FR',
      shiftStartTime: '07:00',
      shiftDurationMinutes: 480,
    },
  ]);

  // ED Shifts
  await db.insert(edShifts).values([
    {
      providerId: DR_OKAFOR_ID,
      locationId: LOC_OKAFOR_ED,
      shiftStart: daysAgo(3),
      shiftEnd: new Date(daysAgo(3).getTime() + 8 * 60 * 60 * 1000),
      patientCount: 14,
      estimatedValue: '1155.00',
      status: 'COMPLETED',
      shiftSource: 'SCHEDULED',
      scheduleId,
    },
    {
      providerId: DR_OKAFOR_ID,
      locationId: LOC_OKAFOR_ED,
      shiftStart: daysAgo(1),
      shiftEnd: new Date(daysAgo(1).getTime() + 10 * 60 * 60 * 1000),
      patientCount: 18,
      estimatedValue: '1485.00',
      status: 'COMPLETED',
      shiftSource: 'SCHEDULED',
      scheduleId,
    },
  ]);

  // Favourite Codes
  await db.insert(favouriteCodes).values([
    { providerId: DR_CHEN_ID, healthServiceCode: '03.03A', displayName: 'Office — Comprehensive', sortOrder: 0 },
    { providerId: DR_CHEN_ID, healthServiceCode: '03.04A', displayName: 'Office — Limited', sortOrder: 1 },
    { providerId: DR_CHEN_ID, healthServiceCode: '03.05A', displayName: 'Office — Follow-up', sortOrder: 2 },
    { providerId: DR_CHEN_ID, healthServiceCode: '03.03J', displayName: 'Telehealth — Comprehensive', sortOrder: 3 },
    { providerId: DR_OKAFOR_ID, healthServiceCode: '13.99A', displayName: 'ED Assessment', sortOrder: 0 },
    { providerId: DR_OKAFOR_ID, healthServiceCode: '03.08A', displayName: 'Hospital Subsequent', sortOrder: 1 },
    { providerId: DR_PATEL_ID, healthServiceCode: '08.19A', displayName: 'IM Consultation', sortOrder: 0 },
    { providerId: DR_PATEL_ID, healthServiceCode: '08.19C', displayName: 'IM Repeat Consult', sortOrder: 1 },
  ]);

  // ========================================================================
  // 16. Claim Templates & Recent Referrers
  // ========================================================================
  console.log('  [16/16] Templates & Referrers...');

  await db.insert(claimTemplates).values([
    {
      physicianId: DR_CHEN_ID,
      name: 'Standard Office Visit',
      templateType: 'CUSTOM',
      claimType: 'AHCIP',
      lineItems: [
        { hsc_code: '03.03A', modifiers: ['CMGP'], di_code: '401' },
      ],
      usageCount: 28,
      isActive: true,
    },
    {
      physicianId: DR_CHEN_ID,
      name: 'Telehealth Follow-up',
      templateType: 'CUSTOM',
      claimType: 'AHCIP',
      lineItems: [
        { hsc_code: '03.05A', modifiers: ['TM'], di_code: '250' },
      ],
      usageCount: 15,
      isActive: true,
    },
    {
      physicianId: DR_OKAFOR_ID,
      name: 'ED Assessment Template',
      templateType: 'SPECIALTY_STARTER',
      claimType: 'AHCIP',
      lineItems: [
        { hsc_code: '13.99A', modifiers: [], di_code: '780' },
      ],
      specialtyCode: '18',
      usageCount: 42,
      isActive: true,
    },
  ]);

  // Recent Referrers
  await db.insert(recentReferrers).values([
    { physicianId: DR_CHEN_ID, referrerCpsa: 'AB99001', referrerName: 'Dr. A. Singh (Cardiology)', useCount: 5, lastUsedAt: daysAgo(3) },
    { physicianId: DR_CHEN_ID, referrerCpsa: 'AB99002', referrerName: 'Dr. B. Lee (Orthopedics)', useCount: 3, lastUsedAt: daysAgo(10) },
    { physicianId: DR_PATEL_ID, referrerCpsa: 'AB99003', referrerName: 'Dr. C. Makokis (GP)', useCount: 8, lastUsedAt: daysAgo(1) },
  ]);

  // Field Mapping Template (for Connect Care imports)
  await db.insert(fieldMappingTemplates).values([
    {
      physicianId: DR_CHEN_ID,
      name: 'Connect Care SCC Export',
      emrType: 'CONNECT_CARE',
      mappings: {
        phn: 'Patient PHN',
        date_of_service: 'Service Date',
        health_service_code: 'Billing Code',
        diagnostic_code: 'ICD-10 Code',
        functional_centre: 'Location Code',
      },
      delimiter: ',',
      hasHeaderRow: true,
      dateFormat: 'YYYY-MM-DD',
    },
  ]);

  // Audit log entry
  await db.insert(auditLog).values([
    {
      userId: DR_CHEN_ID,
      action: 'seed_data_created',
      resourceType: 'system',
      ipAddress: '127.0.0.1',
      userAgent: 'meritum-seed-script/1.0',
      details: { message: 'Test data seeded successfully', physicians: 3, patients: 24, claims: 18 },
    },
  ]);

  console.log('\nSeed complete!');
  console.log('  3 physicians, 1 delegate');
  console.log('  24 patients');
  console.log('  18 claims (15 AHCIP + 3 WCB)');
  console.log('  2 AHCIP batches');
  console.log(`  ${scrapedHsc.length} HSC codes, 10 DI codes, 4 functional centres, ${scrapedModifiers.length} modifiers`);
  console.log(`  ${scrapedHscModifiers.length} HSC modifier eligibility rows`);
  console.log(`  ${scrapedRules.length} governing rules, ${scrapedExplCodes.length} explanatory codes`);
  console.log('  2 AI rules');
  console.log('  3 subscriptions, 2 payments');
  console.log('  5 notifications');
  console.log('  6 help articles, 2 support tickets');
  console.log('  2 ED shifts, 8 favourite codes, 3 claim templates');
  console.log('  8 status components, 2 referral codes');

  await pool.end();
}

main().catch((err) => {
  console.error('Seed failed:', err);
  process.exit(1);
});
