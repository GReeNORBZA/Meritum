import { eq, and, isNull, desc, gte, lte, count, sum, inArray } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  ahcipClaimDetails,
  ahcipBatches,
  type InsertAhcipClaimDetail,
  type SelectAhcipClaimDetail,
  type InsertAhcipBatch,
  type SelectAhcipBatch,
} from '@meritum/shared/schemas/db/ahcip.schema.js';
import {
  claims,
  type SelectClaim,
} from '@meritum/shared/schemas/db/claim.schema.js';
import { patients } from '@meritum/shared/schemas/db/patient.schema.js';
import { ClaimState, ClaimType } from '@meritum/shared/constants/claim.constants.js';
import { AhcipBatchStatus } from '@meritum/shared/constants/ahcip.constants.js';

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export interface AhcipClaimWithDetails {
  claim: SelectClaim;
  detail: SelectAhcipClaimDetail;
  patient: {
    patientId: string;
    firstName: string;
    lastName: string;
    phn: string | null;
    dateOfBirth: string;
  };
}

export interface AhcipClaimForBatch {
  claim: SelectClaim;
  detail: SelectAhcipClaimDetail;
}

export interface ListBatchesFilters {
  status?: string;
  dateFrom?: string;
  dateTo?: string;
  page: number;
  pageSize: number;
}

export interface PaginatedResult<T> {
  data: T[];
  pagination: {
    total: number;
    page: number;
    pageSize: number;
    hasMore: boolean;
  };
}

export interface BatchPreviewGroup {
  baNumber: string;
  claimCount: number;
  totalValue: string;
}

// ---------------------------------------------------------------------------
// AHCIP Repository
// ---------------------------------------------------------------------------

export function createAhcipRepository(db: NodePgDatabase) {
  return {
    /**
     * Insert AHCIP extension row linked to a base claim.
     * Returns the created ahcip_detail_id.
     */
    async createAhcipDetail(
      data: InsertAhcipClaimDetail,
    ): Promise<SelectAhcipClaimDetail> {
      const rows = await db
        .insert(ahcipClaimDetails)
        .values(data)
        .returning();
      return rows[0];
    },

    /**
     * Find AHCIP detail by claim ID, scoped to physician via claims table join.
     * Returns null if not found or wrong physician (no existence leakage).
     * Excludes soft-deleted claims.
     */
    async findAhcipDetailByClaimId(
      claimId: string,
      physicianId: string,
    ): Promise<(SelectAhcipClaimDetail & { claim: SelectClaim }) | null> {
      const rows = await db
        .select({
          detail: ahcipClaimDetails,
          claim: claims,
        })
        .from(ahcipClaimDetails)
        .innerJoin(claims, eq(ahcipClaimDetails.claimId, claims.claimId))
        .where(
          and(
            eq(ahcipClaimDetails.claimId, claimId),
            eq(claims.physicianId, physicianId),
            isNull(claims.deletedAt),
          ),
        )
        .limit(1);

      if (rows.length === 0) {
        return null;
      }

      return { ...rows[0].detail, claim: rows[0].claim };
    },

    /**
     * Update AHCIP-specific fields on an existing detail row.
     * Verifies physician ownership via join to claims table.
     * Returns updated detail or undefined if not found / wrong physician.
     */
    async updateAhcipDetail(
      claimId: string,
      physicianId: string,
      data: Partial<InsertAhcipClaimDetail>,
    ): Promise<SelectAhcipClaimDetail | undefined> {
      // First verify physician ownership via the claims table
      const ownership = await db
        .select({ claimId: claims.claimId })
        .from(claims)
        .where(
          and(
            eq(claims.claimId, claimId),
            eq(claims.physicianId, physicianId),
            isNull(claims.deletedAt),
          ),
        )
        .limit(1);

      if (ownership.length === 0) {
        return undefined;
      }

      const rows = await db
        .update(ahcipClaimDetails)
        .set(data)
        .where(eq(ahcipClaimDetails.claimId, claimId))
        .returning();

      return rows[0];
    },

    /**
     * Full claim + AHCIP details + patient info via joins.
     * For display/validation. Scoped to physician via claims.physician_id.
     * Returns null if not found or wrong physician.
     */
    async findAhcipClaimWithDetails(
      claimId: string,
      physicianId: string,
    ): Promise<AhcipClaimWithDetails | null> {
      const rows = await db
        .select({
          claim: claims,
          detail: ahcipClaimDetails,
          patient: {
            patientId: patients.patientId,
            firstName: patients.firstName,
            lastName: patients.lastName,
            phn: patients.phn,
            dateOfBirth: patients.dateOfBirth,
          },
        })
        .from(ahcipClaimDetails)
        .innerJoin(claims, eq(ahcipClaimDetails.claimId, claims.claimId))
        .innerJoin(patients, eq(claims.patientId, patients.patientId))
        .where(
          and(
            eq(ahcipClaimDetails.claimId, claimId),
            eq(claims.physicianId, physicianId),
            isNull(claims.deletedAt),
          ),
        )
        .limit(1);

      if (rows.length === 0) {
        return null;
      }

      return {
        claim: rows[0].claim,
        detail: rows[0].detail,
        patient: rows[0].patient,
      };
    },

    /**
     * Find queued AHCIP claims for batch assembly.
     * Scoped to physician. Filtered by BA number for PCPCM dual-BA routing.
     * Only includes claims in QUEUED state with claim_type = AHCIP.
     * Optionally filters by isClean flag.
     */
    async listAhcipClaimsForBatch(
      physicianId: string,
      baNumber: string,
      isClean?: boolean,
    ): Promise<AhcipClaimForBatch[]> {
      const conditions = [
        eq(claims.physicianId, physicianId),
        eq(claims.state, ClaimState.QUEUED),
        eq(claims.claimType, ClaimType.AHCIP),
        isNull(claims.deletedAt),
        eq(ahcipClaimDetails.baNumber, baNumber),
      ];

      if (isClean !== undefined) {
        conditions.push(eq(claims.isClean, isClean));
      }

      const rows = await db
        .select({
          claim: claims,
          detail: ahcipClaimDetails,
        })
        .from(ahcipClaimDetails)
        .innerJoin(claims, eq(ahcipClaimDetails.claimId, claims.claimId))
        .where(and(...conditions))
        .orderBy(claims.dateOfService);

      return rows.map((row) => ({
        claim: row.claim,
        detail: row.detail,
      }));
    },

    /**
     * Set assessed_fee and assessment_explanatory_codes after assessment ingestion.
     * Scoped to physician via claims table join.
     * Returns updated detail or undefined if not found / wrong physician.
     */
    async updateAssessmentResult(
      claimId: string,
      physicianId: string,
      assessedFee: string,
      explanatoryCodes: unknown,
    ): Promise<SelectAhcipClaimDetail | undefined> {
      // Verify physician ownership via the claims table
      const ownership = await db
        .select({ claimId: claims.claimId })
        .from(claims)
        .where(
          and(
            eq(claims.claimId, claimId),
            eq(claims.physicianId, physicianId),
            isNull(claims.deletedAt),
          ),
        )
        .limit(1);

      if (ownership.length === 0) {
        return undefined;
      }

      const rows = await db
        .update(ahcipClaimDetails)
        .set({
          assessedFee,
          assessmentExplanatoryCodes: explanatoryCodes,
        })
        .where(eq(ahcipClaimDetails.claimId, claimId))
        .returning();

      return rows[0];
    },

    // =========================================================================
    // AHCIP Batch Operations
    // =========================================================================

    /**
     * Insert a new AHCIP batch with ASSEMBLING status.
     * Returns the created batch with generated ahcip_batch_id.
     * Unique constraint on (physician_id, ba_number, batch_week) prevents duplicates.
     */
    async createAhcipBatch(
      data: InsertAhcipBatch,
    ): Promise<SelectAhcipBatch> {
      const rows = await db
        .insert(ahcipBatches)
        .values({
          ...data,
          status: AhcipBatchStatus.ASSEMBLING,
        })
        .returning();
      return rows[0];
    },

    /**
     * Find a batch by ID, scoped to physician.
     * Returns null if not found or belongs to a different physician.
     */
    async findBatchById(
      batchId: string,
      physicianId: string,
    ): Promise<SelectAhcipBatch | null> {
      const rows = await db
        .select()
        .from(ahcipBatches)
        .where(
          and(
            eq(ahcipBatches.ahcipBatchId, batchId),
            eq(ahcipBatches.physicianId, physicianId),
          ),
        )
        .limit(1);
      return rows[0] ?? null;
    },

    /**
     * Update batch status and optional fields (file_path, file_hash,
     * submission_reference, submitted_at, response_received_at).
     * Physician scoping is enforced by callers who first call findBatchById.
     * Returns updated batch or undefined if not found.
     */
    async updateBatchStatus(
      batchId: string,
      physicianId: string,
      status: string,
      extraFields?: Partial<InsertAhcipBatch>,
    ): Promise<SelectAhcipBatch | undefined> {
      const setClauses: Record<string, unknown> = { status };

      if (extraFields) {
        if (extraFields.filePath !== undefined) setClauses.filePath = extraFields.filePath;
        if (extraFields.fileHash !== undefined) setClauses.fileHash = extraFields.fileHash;
        if (extraFields.submissionReference !== undefined) setClauses.submissionReference = extraFields.submissionReference;
        if (extraFields.submittedAt !== undefined) setClauses.submittedAt = extraFields.submittedAt;
        if (extraFields.responseReceivedAt !== undefined) setClauses.responseReceivedAt = extraFields.responseReceivedAt;
        if (extraFields.claimCount !== undefined) setClauses.claimCount = extraFields.claimCount;
        if (extraFields.totalSubmittedValue !== undefined) setClauses.totalSubmittedValue = extraFields.totalSubmittedValue;
      }

      const rows = await db
        .update(ahcipBatches)
        .set(setClauses)
        .where(
          and(
            eq(ahcipBatches.ahcipBatchId, batchId),
            eq(ahcipBatches.physicianId, physicianId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Paginated list of batches with status and date range filters.
     * Reverse chronological by batch_week.
     * Scoped to physician.
     */
    async listBatches(
      physicianId: string,
      filters: ListBatchesFilters,
    ): Promise<PaginatedResult<SelectAhcipBatch>> {
      const conditions = [
        eq(ahcipBatches.physicianId, physicianId),
      ];

      if (filters.status) {
        conditions.push(eq(ahcipBatches.status, filters.status));
      }

      if (filters.dateFrom) {
        conditions.push(gte(ahcipBatches.batchWeek, filters.dateFrom));
      }

      if (filters.dateTo) {
        conditions.push(lte(ahcipBatches.batchWeek, filters.dateTo));
      }

      const whereClause = and(...conditions);
      const offset = (filters.page - 1) * filters.pageSize;

      const [countResult, rows] = await Promise.all([
        db
          .select({ total: count() })
          .from(ahcipBatches)
          .where(whereClause!),
        db
          .select()
          .from(ahcipBatches)
          .where(whereClause!)
          .orderBy(desc(ahcipBatches.batchWeek))
          .limit(filters.pageSize)
          .offset(offset),
      ]);

      const total = Number(countResult[0]?.total ?? 0);

      return {
        data: rows,
        pagination: {
          total,
          page: filters.page,
          pageSize: filters.pageSize,
          hasMore: filters.page * filters.pageSize < total,
        },
      };
    },

    /**
     * Preview what the next Thursday batch would contain:
     * queued AHCIP claims grouped by BA number with counts and total values.
     * Scoped to physician.
     */
    async findNextBatchPreview(
      physicianId: string,
    ): Promise<BatchPreviewGroup[]> {
      const rows = await db
        .select({
          baNumber: ahcipClaimDetails.baNumber,
          claimCount: count(),
          totalValue: sum(ahcipClaimDetails.submittedFee),
        })
        .from(ahcipClaimDetails)
        .innerJoin(claims, eq(ahcipClaimDetails.claimId, claims.claimId))
        .where(
          and(
            eq(claims.physicianId, physicianId),
            eq(claims.state, ClaimState.QUEUED),
            eq(claims.claimType, ClaimType.AHCIP),
            isNull(claims.deletedAt),
          ),
        )
        .groupBy(ahcipClaimDetails.baNumber);

      return rows.map((row) => ({
        baNumber: row.baNumber,
        claimCount: Number(row.claimCount),
        totalValue: row.totalValue ?? '0.00',
      }));
    },

    /**
     * Find batches in SUBMITTED status awaiting assessment response.
     * Scoped to physician.
     */
    async findBatchesAwaitingResponse(
      physicianId: string,
    ): Promise<SelectAhcipBatch[]> {
      const rows = await db
        .select()
        .from(ahcipBatches)
        .where(
          and(
            eq(ahcipBatches.physicianId, physicianId),
            eq(ahcipBatches.status, AhcipBatchStatus.SUBMITTED),
          ),
        )
        .orderBy(desc(ahcipBatches.batchWeek));
      return rows;
    },

    /**
     * Find all AHCIP claims linked to a specific batch via submitted_batch_id.
     * Returns claims in any state (not filtered by claim state).
     * Used for assessment ingestion and payment reconciliation.
     * Scoped to physician via claims.physician_id.
     */
    async findClaimsByBatchId(
      batchId: string,
      physicianId: string,
    ): Promise<AhcipClaimForBatch[]> {
      const rows = await db
        .select({
          claim: claims,
          detail: ahcipClaimDetails,
        })
        .from(ahcipClaimDetails)
        .innerJoin(claims, eq(ahcipClaimDetails.claimId, claims.claimId))
        .where(
          and(
            eq(claims.physicianId, physicianId),
            eq(claims.submittedBatchId, batchId),
            eq(claims.claimType, ClaimType.AHCIP),
            isNull(claims.deletedAt),
          ),
        )
        .orderBy(claims.dateOfService);

      return rows.map((row) => ({
        claim: row.claim,
        detail: row.detail,
      }));
    },

    /**
     * Find batch for a specific Thursday cycle + BA.
     * Scoped to physician.
     * Returns null if no batch exists for that week/BA combination.
     */
    async findBatchByWeek(
      physicianId: string,
      baNumber: string,
      batchWeek: string,
    ): Promise<SelectAhcipBatch | null> {
      const rows = await db
        .select()
        .from(ahcipBatches)
        .where(
          and(
            eq(ahcipBatches.physicianId, physicianId),
            eq(ahcipBatches.baNumber, baNumber),
            eq(ahcipBatches.batchWeek, batchWeek),
          ),
        )
        .limit(1);
      return rows[0] ?? null;
    },

    /**
     * Link claims to a batch by setting submitted_batch_id.
     * Must be called in the same transaction as batch assembly.
     * Returns the number of claims linked.
     */
    async linkClaimsToBatch(
      claimIds: string[],
      batchId: string,
    ): Promise<number> {
      if (claimIds.length === 0) {
        return 0;
      }

      const rows = await db
        .update(claims)
        .set({
          submittedBatchId: batchId,
          updatedAt: new Date(),
        })
        .where(inArray(claims.claimId, claimIds))
        .returning();

      return rows.length;
    },
  };
}

export type AhcipRepository = ReturnType<typeof createAhcipRepository>;
