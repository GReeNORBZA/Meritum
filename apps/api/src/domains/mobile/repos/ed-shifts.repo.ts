import { eq, and, sql, desc, count } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  edShifts,
  type InsertEdShift,
  type SelectEdShift,
} from '@meritum/shared/schemas/db/mobile.schema.js';
import { claims } from '@meritum/shared/schemas/db/claim.schema.js';
import { ahcipClaimDetails } from '@meritum/shared/schemas/db/ahcip.schema.js';
import { patients } from '@meritum/shared/schemas/db/patient.schema.js';
import { MobileShiftStatus } from '@meritum/shared/constants/mobile.constants.js';
import { ConflictError } from '../../../lib/errors.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ShiftListFilters {
  status?: string;
  limit?: number;
  offset?: number;
}

export interface ShiftClaimSummary {
  claimId: string;
  patientFirstName: string;
  patientLastName: string;
  healthServiceCode: string;
  fee: string | null;
}

export interface ShiftSummary extends SelectEdShift {
  claims: ShiftClaimSummary[];
}

// ---------------------------------------------------------------------------
// ED Shifts Repository
// ---------------------------------------------------------------------------

export function createEdShiftsRepository(db: NodePgDatabase) {
  return {
    /**
     * Create a new ED shift with status ACTIVE.
     * The DB partial unique index enforces one active shift per physician.
     * Throws ConflictError on unique constraint violation.
     */
    async create(
      data: Pick<InsertEdShift, 'providerId' | 'locationId' | 'shiftStart'>,
    ): Promise<SelectEdShift> {
      try {
        const rows = await db
          .insert(edShifts)
          .values({
            providerId: data.providerId,
            locationId: data.locationId,
            shiftStart: data.shiftStart,
            status: MobileShiftStatus.ACTIVE,
            patientCount: 0,
            estimatedValue: '0',
          })
          .returning();
        return rows[0];
      } catch (err: any) {
        // Unique constraint violation: physician already has an active shift
        if (err.code === '23505' && err.constraint?.includes('provider_active')) {
          throw new ConflictError(
            'Physician already has an active shift. End the current shift before starting a new one.',
          );
        }
        throw err;
      }
    },

    /**
     * Get the active shift for this provider.
     * Uses the partial unique index (status = 'ACTIVE').
     * Returns null if no active shift.
     */
    async getActive(providerId: string): Promise<SelectEdShift | null> {
      const rows = await db
        .select()
        .from(edShifts)
        .where(
          and(
            eq(edShifts.providerId, providerId),
            eq(edShifts.status, MobileShiftStatus.ACTIVE),
          ),
        )
        .limit(1);
      return rows[0] ?? null;
    },

    /**
     * Fetch shift by ID scoped to provider.
     * Returns null for wrong provider (404 pattern — don't confirm existence).
     */
    async getById(
      shiftId: string,
      providerId: string,
    ): Promise<SelectEdShift | null> {
      const rows = await db
        .select()
        .from(edShifts)
        .where(
          and(
            eq(edShifts.shiftId, shiftId),
            eq(edShifts.providerId, providerId),
          ),
        )
        .limit(1);
      return rows[0] ?? null;
    },

    /**
     * End an active shift: set shift_end = now(), status = 'ENDED'.
     * Recalculates patient_count and estimated_value from linked claims.
     * Returns updated shift, or null if not found / wrong provider.
     */
    async endShift(
      shiftId: string,
      providerId: string,
    ): Promise<SelectEdShift | null> {
      // Recalculate from linked claims + AHCIP details
      const aggregateResult = await db
        .select({
          claimCount: count(),
          totalValue: sql<string>`COALESCE(SUM(COALESCE(${ahcipClaimDetails.submittedFee}, 0)), 0)::text`,
        })
        .from(claims)
        .leftJoin(ahcipClaimDetails, eq(claims.claimId, ahcipClaimDetails.claimId))
        .where(
          and(
            eq(claims.shiftId, shiftId),
            eq(claims.physicianId, providerId),
          ),
        );

      const claimCount = Number(aggregateResult[0]?.claimCount ?? 0);
      const totalValue = aggregateResult[0]?.totalValue ?? '0';

      const rows = await db
        .update(edShifts)
        .set({
          shiftEnd: new Date(),
          status: MobileShiftStatus.ENDED,
          patientCount: claimCount,
          estimatedValue: totalValue,
        })
        .where(
          and(
            eq(edShifts.shiftId, shiftId),
            eq(edShifts.providerId, providerId),
            eq(edShifts.status, MobileShiftStatus.ACTIVE),
          ),
        )
        .returning();

      return rows[0] ?? null;
    },

    /**
     * Mark a shift as REVIEWED. Called when physician reviews all shift
     * claims on desktop. Only ENDED shifts can be marked reviewed.
     * Returns updated shift, or null if not found / wrong provider / wrong state.
     */
    async markReviewed(
      shiftId: string,
      providerId: string,
    ): Promise<SelectEdShift | null> {
      const rows = await db
        .update(edShifts)
        .set({ status: MobileShiftStatus.REVIEWED })
        .where(
          and(
            eq(edShifts.shiftId, shiftId),
            eq(edShifts.providerId, providerId),
            eq(edShifts.status, MobileShiftStatus.ENDED),
          ),
        )
        .returning();

      return rows[0] ?? null;
    },

    /**
     * List shifts for a provider with optional status filter.
     * Paginated by limit/offset. Ordered by created_at DESC.
     */
    async list(
      providerId: string,
      filters?: ShiftListFilters,
    ): Promise<{ data: SelectEdShift[]; total: number }> {
      const limit = filters?.limit ?? 20;
      const offset = filters?.offset ?? 0;

      const conditions = [eq(edShifts.providerId, providerId)];
      if (filters?.status) {
        conditions.push(eq(edShifts.status, filters.status));
      }

      const whereClause = and(...conditions);

      const [countResult, rows] = await Promise.all([
        db
          .select({ total: count() })
          .from(edShifts)
          .where(whereClause),
        db
          .select()
          .from(edShifts)
          .where(whereClause)
          .orderBy(desc(edShifts.createdAt))
          .limit(limit)
          .offset(offset),
      ]);

      const total = Number(countResult[0]?.total ?? 0);
      return { data: rows, total };
    },

    /**
     * Atomically increment patient_count by 1 and add feeAmount to
     * estimated_value. Called after logging a patient encounter.
     * Uses atomic SQL (SET patient_count = patient_count + 1) to prevent
     * race conditions.
     * Returns updated shift, or null if not found / wrong provider.
     */
    async incrementPatientCount(
      shiftId: string,
      providerId: string,
      feeAmount: string,
    ): Promise<SelectEdShift | null> {
      const rows = await db
        .update(edShifts)
        .set({
          patientCount: sql`${edShifts.patientCount} + 1`,
          estimatedValue: sql`(${edShifts.estimatedValue}::decimal + ${feeAmount}::decimal)::text`,
        })
        .where(
          and(
            eq(edShifts.shiftId, shiftId),
            eq(edShifts.providerId, providerId),
            eq(edShifts.status, MobileShiftStatus.ACTIVE),
          ),
        )
        .returning();

      return rows[0] ?? null;
    },

    /**
     * Return shift details plus list of claim IDs and basic claim data
     * (patient name, HSC code, fee) linked to this shift.
     * Scoped to provider.
     */
    async getSummary(
      shiftId: string,
      providerId: string,
    ): Promise<ShiftSummary | null> {
      // Get the shift first
      const shiftRows = await db
        .select()
        .from(edShifts)
        .where(
          and(
            eq(edShifts.shiftId, shiftId),
            eq(edShifts.providerId, providerId),
          ),
        )
        .limit(1);

      const shift = shiftRows[0];
      if (!shift) {
        return null;
      }

      // Get linked claims with patient info and AHCIP details
      const claimRows = await db
        .select({
          claimId: claims.claimId,
          patientFirstName: patients.firstName,
          patientLastName: patients.lastName,
          healthServiceCode: sql<string>`COALESCE(${ahcipClaimDetails.healthServiceCode}, '')`,
          fee: sql<string | null>`${ahcipClaimDetails.submittedFee}::text`,
        })
        .from(claims)
        .innerJoin(patients, eq(claims.patientId, patients.patientId))
        .leftJoin(ahcipClaimDetails, eq(claims.claimId, ahcipClaimDetails.claimId))
        .where(
          and(
            eq(claims.shiftId, shiftId),
            eq(claims.physicianId, providerId),
          ),
        );

      return {
        ...shift,
        claims: claimRows,
      };
    },
  };
}

export type EdShiftsRepository = ReturnType<typeof createEdShiftsRepository>;
