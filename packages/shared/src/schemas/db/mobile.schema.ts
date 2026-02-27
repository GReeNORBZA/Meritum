// ============================================================================
// Domain 10: Mobile Companion — Drizzle DB Schema
// ============================================================================

import {
  pgTable,
  uuid,
  varchar,
  boolean,
  integer,
  decimal,
  text,
  jsonb,
  timestamp,
  index,
  uniqueIndex,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { providers } from './provider.schema.js';
import { practiceLocations } from './provider.schema.js';
import { claims } from './claim.schema.js';

// --- Shift Schedules Table (FRD MOB-002 §3.1) ---
// Stores recurring shift schedules using iCal RRULE format.
// Physician-scoped via provider_id (HIA custodian boundary).
// Shifts are auto-expanded up to 90 days ahead.

export const shiftSchedules = pgTable(
  'shift_schedules',
  {
    scheduleId: uuid('schedule_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => providers.providerId),
    locationId: uuid('location_id')
      .notNull()
      .references(() => practiceLocations.locationId),
    name: varchar('name', { length: 100 }).notNull(),
    rrule: text('rrule').notNull(),
    shiftStartTime: varchar('shift_start_time', { length: 5 }).notNull(),
    shiftDurationMinutes: integer('shift_duration_minutes').notNull(),
    isActive: boolean('is_active').notNull().default(true),
    lastExpandedAt: timestamp('last_expanded_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('shift_schedules_provider_active_idx').on(
      table.providerId,
      table.isActive,
    ),
  ],
);

// --- ED Shifts Table ---
// Tracks emergency department shift sessions for the Mobile Companion.
// Physician-scoped via provider_id (HIA custodian boundary).
// Only one ACTIVE shift per physician at any time (enforced via partial unique index).
// Claims reference shift_id to associate encounters with a shift session.

export const edShifts = pgTable(
  'ed_shifts',
  {
    shiftId: uuid('shift_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => providers.providerId),
    locationId: uuid('location_id')
      .notNull()
      .references(() => practiceLocations.locationId),
    shiftStart: timestamp('shift_start', { withTimezone: true }).notNull(),
    shiftEnd: timestamp('shift_end', { withTimezone: true }),
    patientCount: integer('patient_count').notNull().default(0),
    estimatedValue: decimal('estimated_value', { precision: 10, scale: 2 })
      .notNull()
      .default('0'),
    status: varchar('status', { length: 20 }).notNull().default('ACTIVE'),
    shiftSource: varchar('shift_source', { length: 20 }).notNull().default('MANUAL'),
    inferredConfirmed: boolean('inferred_confirmed').default(false),
    scheduleId: uuid('schedule_id').references(
      () => shiftSchedules.scheduleId,
    ),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    // Enforces max one active shift per physician at the DB level
    uniqueIndex('ed_shifts_provider_active_unique_idx')
      .on(table.providerId)
      .where(sql`status = 'ACTIVE'`),

    // Active shift lookups by physician
    index('ed_shifts_provider_status_idx').on(table.providerId, table.status),

    // Shift history listing (newest first)
    index('ed_shifts_provider_created_idx').on(
      table.providerId,
      table.createdAt,
    ),

    // Schedule-based lookups
    index('ed_shifts_schedule_idx').on(table.scheduleId),
  ],
);

// --- Favourite Codes Table ---
// Stores physician's favourite health service codes for quick claim entry.
// Max 30 favourites per physician (enforced at service layer).
// Physician-scoped via provider_id (HIA custodian boundary).

export const favouriteCodes = pgTable(
  'favourite_codes',
  {
    favouriteId: uuid('favourite_id').primaryKey().defaultRandom(),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => providers.providerId),
    healthServiceCode: varchar('health_service_code', { length: 10 }).notNull(),
    displayName: varchar('display_name', { length: 100 }),
    sortOrder: integer('sort_order').notNull(),
    defaultModifiers: jsonb('default_modifiers').$type<string[]>(),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    // No duplicate favourites per physician
    uniqueIndex('favourite_codes_provider_hsc_unique_idx').on(
      table.providerId,
      table.healthServiceCode,
    ),

    // Ordered retrieval by physician
    index('favourite_codes_provider_sort_idx').on(
      table.providerId,
      table.sortOrder,
    ),
  ],
);

// --- ED Shift Encounters Table (FRD MOB-002 §4.1) ---
// Individual patient encounters logged during a shift session.
// Physician-scoped via provider_id (HIA custodian boundary).
// Supports 4 PHN capture methods: barcode, search, manual, last-4.

export const edShiftEncounters = pgTable(
  'ed_shift_encounters',
  {
    encounterId: uuid('encounter_id').primaryKey().defaultRandom(),
    shiftId: uuid('shift_id')
      .notNull()
      .references(() => edShifts.shiftId),
    providerId: uuid('provider_id')
      .notNull()
      .references(() => providers.providerId),
    phn: varchar('phn', { length: 9 }),
    phnCaptureMethod: varchar('phn_capture_method', { length: 20 }).notNull(),
    phnIsPartial: boolean('phn_is_partial').notNull().default(false),
    healthServiceCode: varchar('health_service_code', { length: 10 }),
    modifiers: jsonb('modifiers').$type<string[]>(),
    diCode: varchar('di_code', { length: 10 }),
    freeTextTag: varchar('free_text_tag', { length: 100 }),
    matchedClaimId: uuid('matched_claim_id').references(() => claims.claimId),
    encounterTimestamp: timestamp('encounter_timestamp', {
      withTimezone: true,
    }).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('ed_shift_encounters_shift_idx').on(table.shiftId),
    index('ed_shift_encounters_provider_created_idx').on(
      table.providerId,
      table.createdAt,
    ),
    index('ed_shift_encounters_phn_idx').on(table.phn),
    index('ed_shift_encounters_matched_claim_idx').on(table.matchedClaimId),
  ],
);

// --- Inferred Types ---

export type InsertShiftSchedule = typeof shiftSchedules.$inferInsert;
export type SelectShiftSchedule = typeof shiftSchedules.$inferSelect;

export type InsertEdShift = typeof edShifts.$inferInsert;
export type SelectEdShift = typeof edShifts.$inferSelect;

export type InsertEdShiftEncounter = typeof edShiftEncounters.$inferInsert;
export type SelectEdShiftEncounter = typeof edShiftEncounters.$inferSelect;

export type InsertFavouriteCode = typeof favouriteCodes.$inferInsert;
export type SelectFavouriteCode = typeof favouriteCodes.$inferSelect;
