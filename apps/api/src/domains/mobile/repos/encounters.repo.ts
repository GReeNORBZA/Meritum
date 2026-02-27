// ============================================================================
// Domain 10: Mobile Companion — Encounters Repository (MOB-002 §4)
// ============================================================================

import { eq, and, desc } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  edShiftEncounters,
  edShifts,
  type InsertEdShiftEncounter,
  type SelectEdShiftEncounter,
} from '@meritum/shared/schemas/db/mobile.schema.js';
import { MobileShiftStatus } from '@meritum/shared/constants/mobile.constants.js';
import { BusinessRuleError, NotFoundError } from '../../../lib/errors.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CreateEncounterData = Pick<
  InsertEdShiftEncounter,
  | 'shiftId'
  | 'providerId'
  | 'phn'
  | 'phnCaptureMethod'
  | 'phnIsPartial'
  | 'healthServiceCode'
  | 'modifiers'
  | 'diCode'
  | 'freeTextTag'
  | 'encounterTimestamp'
>;

// ---------------------------------------------------------------------------
// Encounters Repository
// ---------------------------------------------------------------------------

export function createEncountersRepository(db: NodePgDatabase) {
  return {
    /**
     * Log a new encounter for an active shift.
     * Validates that the shift is ACTIVE before inserting.
     * Scoped to provider for security.
     */
    async logEncounter(
      data: CreateEncounterData,
    ): Promise<SelectEdShiftEncounter> {
      // Validate shift is active and belongs to provider
      const shiftRows = await db
        .select()
        .from(edShifts)
        .where(
          and(
            eq(edShifts.shiftId, data.shiftId),
            eq(edShifts.providerId, data.providerId),
          ),
        )
        .limit(1);

      const shift = shiftRows[0];
      if (!shift) {
        throw new NotFoundError('Shift');
      }
      if (shift.status !== MobileShiftStatus.ACTIVE) {
        throw new BusinessRuleError(
          'Cannot log encounters to a shift that is not active',
        );
      }

      const rows = await db
        .insert(edShiftEncounters)
        .values({
          shiftId: data.shiftId,
          providerId: data.providerId,
          phn: data.phn ?? null,
          phnCaptureMethod: data.phnCaptureMethod,
          phnIsPartial: data.phnIsPartial ?? false,
          healthServiceCode: data.healthServiceCode ?? null,
          modifiers: data.modifiers ?? null,
          diCode: data.diCode ?? null,
          freeTextTag: data.freeTextTag ?? null,
          encounterTimestamp: data.encounterTimestamp,
        })
        .returning();

      return rows[0];
    },

    /**
     * List all encounters for a shift, scoped to provider.
     * Ordered by encounter_timestamp DESC (most recent first).
     */
    async listEncounters(
      shiftId: string,
      providerId: string,
    ): Promise<SelectEdShiftEncounter[]> {
      return db
        .select()
        .from(edShiftEncounters)
        .where(
          and(
            eq(edShiftEncounters.shiftId, shiftId),
            eq(edShiftEncounters.providerId, providerId),
          ),
        )
        .orderBy(desc(edShiftEncounters.encounterTimestamp));
    },

    /**
     * Delete an encounter by ID. Must belong to the same shift and provider.
     * Returns the deleted encounter, or null if not found.
     */
    async deleteEncounter(
      encounterId: string,
      shiftId: string,
      providerId: string,
    ): Promise<SelectEdShiftEncounter | null> {
      // Verify ownership
      const existing = await db
        .select()
        .from(edShiftEncounters)
        .where(
          and(
            eq(edShiftEncounters.encounterId, encounterId),
            eq(edShiftEncounters.shiftId, shiftId),
            eq(edShiftEncounters.providerId, providerId),
          ),
        )
        .limit(1);

      if (!existing[0]) {
        return null;
      }

      const rows = await db
        .delete(edShiftEncounters)
        .where(
          and(
            eq(edShiftEncounters.encounterId, encounterId),
            eq(edShiftEncounters.shiftId, shiftId),
            eq(edShiftEncounters.providerId, providerId),
          ),
        )
        .returning();

      return rows[0] ?? null;
    },

    /**
     * Get a single encounter by ID, scoped to provider.
     */
    async getById(
      encounterId: string,
      providerId: string,
    ): Promise<SelectEdShiftEncounter | null> {
      const rows = await db
        .select()
        .from(edShiftEncounters)
        .where(
          and(
            eq(edShiftEncounters.encounterId, encounterId),
            eq(edShiftEncounters.providerId, providerId),
          ),
        )
        .limit(1);
      return rows[0] ?? null;
    },
  };
}

export type EncountersRepository = ReturnType<typeof createEncountersRepository>;
