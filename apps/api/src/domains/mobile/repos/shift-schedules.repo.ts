// ============================================================================
// Domain 10: Mobile Companion — Shift Schedules Repository (MOB-002 §3.1)
// ============================================================================

import { eq, and, desc } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  shiftSchedules,
  type InsertShiftSchedule,
  type SelectShiftSchedule,
} from '@meritum/shared/schemas/db/mobile.schema.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CreateShiftScheduleData = Pick<
  InsertShiftSchedule,
  'providerId' | 'locationId' | 'name' | 'rrule' | 'shiftStartTime' | 'shiftDurationMinutes'
>;

export type UpdateShiftScheduleData = Partial<
  Pick<InsertShiftSchedule, 'name' | 'rrule' | 'shiftStartTime' | 'shiftDurationMinutes' | 'isActive'>
>;

// ---------------------------------------------------------------------------
// Shift Schedules Repository
// ---------------------------------------------------------------------------

export function createShiftSchedulesRepository(db: NodePgDatabase) {
  return {
    /**
     * Create a new shift schedule for a provider.
     */
    async create(data: CreateShiftScheduleData): Promise<SelectShiftSchedule> {
      const rows = await db
        .insert(shiftSchedules)
        .values({
          providerId: data.providerId,
          locationId: data.locationId,
          name: data.name,
          rrule: data.rrule,
          shiftStartTime: data.shiftStartTime,
          shiftDurationMinutes: data.shiftDurationMinutes,
          isActive: true,
        })
        .returning();
      return rows[0];
    },

    /**
     * Get a schedule by ID, scoped to provider.
     * Returns null for wrong provider (404 pattern).
     */
    async getById(
      scheduleId: string,
      providerId: string,
    ): Promise<SelectShiftSchedule | null> {
      const rows = await db
        .select()
        .from(shiftSchedules)
        .where(
          and(
            eq(shiftSchedules.scheduleId, scheduleId),
            eq(shiftSchedules.providerId, providerId),
          ),
        )
        .limit(1);
      return rows[0] ?? null;
    },

    /**
     * Update a shift schedule. Only provider-owned schedules can be updated.
     * Returns updated schedule, or null if not found / wrong provider.
     */
    async update(
      scheduleId: string,
      providerId: string,
      data: UpdateShiftScheduleData,
    ): Promise<SelectShiftSchedule | null> {
      const rows = await db
        .update(shiftSchedules)
        .set({
          ...data,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(shiftSchedules.scheduleId, scheduleId),
            eq(shiftSchedules.providerId, providerId),
          ),
        )
        .returning();
      return rows[0] ?? null;
    },

    /**
     * Soft-delete: deactivate a schedule by setting isActive = false.
     * Returns updated schedule, or null if not found / wrong provider.
     */
    async delete(
      scheduleId: string,
      providerId: string,
    ): Promise<SelectShiftSchedule | null> {
      const rows = await db
        .update(shiftSchedules)
        .set({
          isActive: false,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(shiftSchedules.scheduleId, scheduleId),
            eq(shiftSchedules.providerId, providerId),
          ),
        )
        .returning();
      return rows[0] ?? null;
    },

    /**
     * List all schedules for a provider. Active schedules first,
     * then ordered by createdAt DESC.
     */
    async list(
      providerId: string,
      activeOnly = false,
    ): Promise<SelectShiftSchedule[]> {
      const conditions = [eq(shiftSchedules.providerId, providerId)];
      if (activeOnly) {
        conditions.push(eq(shiftSchedules.isActive, true));
      }

      return db
        .select()
        .from(shiftSchedules)
        .where(and(...conditions))
        .orderBy(desc(shiftSchedules.isActive), desc(shiftSchedules.createdAt));
    },

    /**
     * Update lastExpandedAt timestamp after RRULE expansion.
     */
    async updateLastExpanded(
      scheduleId: string,
      providerId: string,
    ): Promise<void> {
      await db
        .update(shiftSchedules)
        .set({ lastExpandedAt: new Date() })
        .where(
          and(
            eq(shiftSchedules.scheduleId, scheduleId),
            eq(shiftSchedules.providerId, providerId),
          ),
        );
    },
  };
}

export type ShiftSchedulesRepository = ReturnType<typeof createShiftSchedulesRepository>;
