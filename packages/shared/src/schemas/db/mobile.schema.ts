// ============================================================================
// Domain 10: Mobile Companion — Drizzle DB Schema
// ============================================================================

import {
  pgTable,
  uuid,
  varchar,
  integer,
  decimal,
  jsonb,
  timestamp,
  index,
  uniqueIndex,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { providers } from './provider.schema.js';
import { practiceLocations } from './provider.schema.js';

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

// --- Inferred Types ---

export type InsertEdShift = typeof edShifts.$inferInsert;
export type SelectEdShift = typeof edShifts.$inferSelect;

export type InsertFavouriteCode = typeof favouriteCodes.$inferInsert;
export type SelectFavouriteCode = typeof favouriteCodes.$inferSelect;
