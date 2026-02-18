import {
  eq,
  and,
  desc,
  count,
  sql,
  isNull,
  lte,
  gte,
  inArray,
} from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  claims,
  importBatches,
  fieldMappingTemplates,
  shifts,
  claimExports,
  claimAuditHistory,
  type InsertClaim,
  type SelectClaim,
  type InsertImportBatch,
  type SelectImportBatch,
  type InsertFieldMappingTemplate,
  type SelectFieldMappingTemplate,
  type InsertShift,
  type SelectShift,
  type InsertClaimExport,
  type SelectClaimExport,
  type InsertClaimAuditHistory,
  type SelectClaimAuditHistory,
} from '@meritum/shared/schemas/db/claim.schema.js';
import { ClaimState, ShiftStatus, ExportStatus } from '@meritum/shared/constants/claim.constants.js';
import { ConflictError } from '../../lib/errors.js';

// ---------------------------------------------------------------------------
// Filter types
// ---------------------------------------------------------------------------

export interface ListClaimsFilters {
  state?: string;
  claimType?: string;
  dateFrom?: string;
  dateTo?: string;
  patientId?: string;
  isClean?: boolean;
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

export interface ClaimStateCount {
  state: string;
  count: number;
}

export interface ValidationResult {
  checks: Array<{
    checkId: string;
    severity: string;
    passed: boolean;
    message?: string;
  }>;
  isValid: boolean;
}

// ---------------------------------------------------------------------------
// Claim Repository
// ---------------------------------------------------------------------------

export function createClaimRepository(db: NodePgDatabase) {
  return {
    /**
     * Insert a new claim with state = DRAFT.
     * import_source comes from the input data.
     */
    async createClaim(data: InsertClaim): Promise<SelectClaim> {
      const rows = await db
        .insert(claims)
        .values({
          ...data,
          state: ClaimState.DRAFT,
        })
        .returning();
      return rows[0];
    },

    /**
     * Find a claim by ID, scoped to physician.
     * Returns undefined if not found or belongs to a different physician.
     * Excludes soft-deleted claims.
     */
    async findClaimById(
      claimId: string,
      physicianId: string,
    ): Promise<SelectClaim | undefined> {
      const rows = await db
        .select()
        .from(claims)
        .where(
          and(
            eq(claims.claimId, claimId),
            eq(claims.physicianId, physicianId),
            isNull(claims.deletedAt),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * Update claim fields. Sets updated_at to now().
     * Scoped to physician — returns undefined if not found or not owned.
     * Excludes soft-deleted claims.
     */
    async updateClaim(
      claimId: string,
      physicianId: string,
      data: Partial<InsertClaim>,
    ): Promise<SelectClaim | undefined> {
      const rows = await db
        .update(claims)
        .set({ ...data, updatedAt: new Date() })
        .where(
          and(
            eq(claims.claimId, claimId),
            eq(claims.physicianId, physicianId),
            isNull(claims.deletedAt),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Soft-delete a claim by setting deleted_at.
     * Only allowed when state = DRAFT.
     * Scoped to physician — returns false if not found, not owned, or wrong state.
     */
    async softDeleteClaim(
      claimId: string,
      physicianId: string,
    ): Promise<boolean> {
      const rows = await db
        .update(claims)
        .set({ deletedAt: new Date(), state: ClaimState.DELETED, updatedAt: new Date() })
        .where(
          and(
            eq(claims.claimId, claimId),
            eq(claims.physicianId, physicianId),
            eq(claims.state, ClaimState.DRAFT),
            isNull(claims.deletedAt),
          ),
        )
        .returning();
      return rows.length > 0;
    },

    /**
     * Paginated list of claims with filters, scoped to physician.
     * Excludes soft-deleted claims. Reverse chronological order.
     */
    async listClaims(
      physicianId: string,
      filters: ListClaimsFilters,
    ): Promise<PaginatedResult<SelectClaim>> {
      const conditions = [
        eq(claims.physicianId, physicianId),
        isNull(claims.deletedAt),
      ];

      if (filters.state) {
        conditions.push(eq(claims.state, filters.state));
      }

      if (filters.claimType) {
        conditions.push(eq(claims.claimType, filters.claimType));
      }

      if (filters.dateFrom) {
        conditions.push(gte(claims.dateOfService, filters.dateFrom));
      }

      if (filters.dateTo) {
        conditions.push(lte(claims.dateOfService, filters.dateTo));
      }

      if (filters.patientId) {
        conditions.push(eq(claims.patientId, filters.patientId));
      }

      if (filters.isClean !== undefined) {
        conditions.push(eq(claims.isClean, filters.isClean));
      }

      const whereClause = and(...conditions);
      const offset = (filters.page - 1) * filters.pageSize;

      const [countResult, rows] = await Promise.all([
        db
          .select({ total: count() })
          .from(claims)
          .where(whereClause!),
        db
          .select()
          .from(claims)
          .where(whereClause!)
          .orderBy(desc(claims.createdAt))
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
     * Count claims grouped by state for dashboard.
     * Scoped to physician. Excludes soft-deleted claims.
     */
    async countClaimsByState(
      physicianId: string,
    ): Promise<ClaimStateCount[]> {
      const rows = await db
        .select({
          state: claims.state,
          count: count(),
        })
        .from(claims)
        .where(
          and(
            eq(claims.physicianId, physicianId),
            isNull(claims.deletedAt),
          ),
        )
        .groupBy(claims.state);

      return rows.map((r) => ({
        state: r.state,
        count: Number(r.count),
      }));
    },

    /**
     * Find claims within N days of submission_deadline.
     * Only non-terminal, non-deleted claims. Scoped to physician.
     */
    async findClaimsApproachingDeadline(
      physicianId: string,
      daysThreshold: number,
    ): Promise<SelectClaim[]> {
      const thresholdDate = new Date();
      thresholdDate.setDate(thresholdDate.getDate() + daysThreshold);
      const thresholdStr = thresholdDate.toISOString().split('T')[0];

      const rows = await db
        .select()
        .from(claims)
        .where(
          and(
            eq(claims.physicianId, physicianId),
            isNull(claims.deletedAt),
            lte(claims.submissionDeadline, thresholdStr),
            gte(claims.submissionDeadline, new Date().toISOString().split('T')[0]),
            sql`${claims.state} NOT IN ('PAID', 'ADJUSTED', 'WRITTEN_OFF', 'EXPIRED', 'DELETED')`,
          ),
        )
        .orderBy(claims.submissionDeadline);

      return rows;
    },

    /**
     * Atomic state transition with optimistic concurrency.
     * Verifies current state matches fromState before transitioning.
     * Returns updated claim or throws ConflictError on state mismatch.
     * Physician-scoped through the calling service layer.
     */
    async transitionState(
      claimId: string,
      physicianId: string,
      fromState: string,
      toState: string,
    ): Promise<SelectClaim> {
      const rows = await db
        .update(claims)
        .set({ state: toState, updatedAt: new Date() })
        .where(
          and(
            eq(claims.claimId, claimId),
            eq(claims.physicianId, physicianId),
            eq(claims.state, fromState),
            isNull(claims.deletedAt),
          ),
        )
        .returning();

      if (rows.length === 0) {
        throw new ConflictError(
          `State transition failed: claim is not in expected state`,
        );
      }

      return rows[0];
    },

    /**
     * Set is_clean flag on a claim. Called when claim enters QUEUED state.
     * Physician-scoped.
     */
    async classifyClaim(
      claimId: string,
      physicianId: string,
      isClean: boolean,
    ): Promise<SelectClaim | undefined> {
      const rows = await db
        .update(claims)
        .set({ isClean, updatedAt: new Date() })
        .where(
          and(
            eq(claims.claimId, claimId),
            eq(claims.physicianId, physicianId),
            isNull(claims.deletedAt),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Store structured validation result with timestamp and reference data version.
     * Physician-scoped.
     */
    async updateValidationResult(
      claimId: string,
      physicianId: string,
      result: ValidationResult,
      version: string,
    ): Promise<SelectClaim | undefined> {
      const rows = await db
        .update(claims)
        .set({
          validationResult: result,
          validationTimestamp: new Date(),
          referenceDataVersion: version,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(claims.claimId, claimId),
            eq(claims.physicianId, physicianId),
            isNull(claims.deletedAt),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Set ai_coach_suggestions JSONB. Physician-scoped.
     */
    async updateAiSuggestions(
      claimId: string,
      physicianId: string,
      suggestions: unknown,
    ): Promise<SelectClaim | undefined> {
      const rows = await db
        .update(claims)
        .set({ aiCoachSuggestions: suggestions, updatedAt: new Date() })
        .where(
          and(
            eq(claims.claimId, claimId),
            eq(claims.physicianId, physicianId),
            isNull(claims.deletedAt),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Set duplicate_alert JSONB. Physician-scoped.
     */
    async updateDuplicateAlert(
      claimId: string,
      physicianId: string,
      alert: unknown,
    ): Promise<SelectClaim | undefined> {
      const rows = await db
        .update(claims)
        .set({ duplicateAlert: alert, updatedAt: new Date() })
        .where(
          and(
            eq(claims.claimId, claimId),
            eq(claims.physicianId, physicianId),
            isNull(claims.deletedAt),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Set flags JSONB. Physician-scoped.
     */
    async updateFlags(
      claimId: string,
      physicianId: string,
      flags: unknown,
    ): Promise<SelectClaim | undefined> {
      const rows = await db
        .update(claims)
        .set({ flags, updatedAt: new Date() })
        .where(
          and(
            eq(claims.claimId, claimId),
            eq(claims.physicianId, physicianId),
            isNull(claims.deletedAt),
          ),
        )
        .returning();
      return rows[0];
    },

    // =========================================================================
    // Import Batch Operations
    // =========================================================================

    /**
     * Insert a new import batch record with PENDING status.
     * Physician-scoped via data.physicianId.
     */
    async createImportBatch(
      data: InsertImportBatch,
    ): Promise<SelectImportBatch> {
      const rows = await db
        .insert(importBatches)
        .values(data)
        .returning();
      return rows[0];
    },

    /**
     * Find an import batch by ID, scoped to physician.
     * Returns undefined if not found or belongs to a different physician.
     */
    async findImportBatchById(
      batchId: string,
      physicianId: string,
    ): Promise<SelectImportBatch | undefined> {
      const rows = await db
        .select()
        .from(importBatches)
        .where(
          and(
            eq(importBatches.importBatchId, batchId),
            eq(importBatches.physicianId, physicianId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * Update import batch status and optional counts after processing.
     * Physician-scoped via batchId lookup (caller must verify ownership).
     */
    async updateImportBatchStatus(
      batchId: string,
      physicianId: string,
      status: string,
      counts?: {
        successCount?: number;
        errorCount?: number;
        errorDetails?: unknown;
      },
    ): Promise<SelectImportBatch | undefined> {
      const setClauses: Record<string, unknown> = { status };
      if (counts?.successCount !== undefined) {
        setClauses.successCount = counts.successCount;
      }
      if (counts?.errorCount !== undefined) {
        setClauses.errorCount = counts.errorCount;
      }
      if (counts?.errorDetails !== undefined) {
        setClauses.errorDetails = counts.errorDetails;
      }

      const rows = await db
        .update(importBatches)
        .set(setClauses)
        .where(
          and(
            eq(importBatches.importBatchId, batchId),
            eq(importBatches.physicianId, physicianId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Check if a file with this SHA-256 hash was already imported by this physician.
     * Returns the existing import batch if found, undefined otherwise.
     */
    async findDuplicateImportByHash(
      physicianId: string,
      fileHash: string,
    ): Promise<SelectImportBatch | undefined> {
      const rows = await db
        .select()
        .from(importBatches)
        .where(
          and(
            eq(importBatches.physicianId, physicianId),
            eq(importBatches.fileHash, fileHash),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * Paginated list of import batches, reverse chronological.
     * Physician-scoped.
     */
    async listImportBatches(
      physicianId: string,
      page: number,
      pageSize: number,
    ): Promise<PaginatedResult<SelectImportBatch>> {
      const whereClause = eq(importBatches.physicianId, physicianId);
      const offset = (page - 1) * pageSize;

      const [countResult, rows] = await Promise.all([
        db
          .select({ total: count() })
          .from(importBatches)
          .where(whereClause),
        db
          .select()
          .from(importBatches)
          .where(whereClause)
          .orderBy(desc(importBatches.createdAt))
          .limit(pageSize)
          .offset(offset),
      ]);

      const total = Number(countResult[0]?.total ?? 0);

      return {
        data: rows,
        pagination: {
          total,
          page,
          pageSize,
          hasMore: page * pageSize < total,
        },
      };
    },

    /**
     * Find claims in QUEUED state matching criteria for batch assembly.
     * Physician-scoped. Filters by claim type and clean/flagged status.
     */
    async findClaimsForBatchAssembly(
      physicianId: string,
      claimType: string,
      includeClean: boolean,
      includeFlagged: boolean,
    ): Promise<SelectClaim[]> {
      const conditions = [
        eq(claims.physicianId, physicianId),
        eq(claims.state, ClaimState.QUEUED),
        eq(claims.claimType, claimType),
        isNull(claims.deletedAt),
      ];

      // Filter by clean/flagged classification
      if (includeClean && !includeFlagged) {
        conditions.push(eq(claims.isClean, true));
      } else if (includeFlagged && !includeClean) {
        conditions.push(eq(claims.isClean, false));
      }
      // If both are true, no isClean filter needed (include all)
      // If both are false, return nothing — handled by conditions that can't match

      if (!includeClean && !includeFlagged) {
        return [];
      }

      const rows = await db
        .select()
        .from(claims)
        .where(and(...conditions))
        .orderBy(claims.dateOfService);

      return rows;
    },

    /**
     * Batch state transition for submission. Atomic — all or nothing.
     * Sets submitted_batch_id on all claims. Verifies all claims are in
     * fromState to prevent partial batch assembly.
     * Physician-scoped through the calling service layer.
     */
    async bulkTransitionState(
      claimIds: string[],
      physicianId: string,
      fromState: string,
      toState: string,
      batchId: string,
    ): Promise<SelectClaim[]> {
      if (claimIds.length === 0) {
        return [];
      }

      const rows = await db
        .update(claims)
        .set({
          state: toState,
          submittedBatchId: batchId,
          updatedAt: new Date(),
        })
        .where(
          and(
            inArray(claims.claimId, claimIds),
            eq(claims.physicianId, physicianId),
            eq(claims.state, fromState),
            isNull(claims.deletedAt),
          ),
        )
        .returning();

      // If not all claims were transitioned, we have a partial match — conflict
      if (rows.length !== claimIds.length) {
        throw new ConflictError(
          `Bulk state transition failed: expected ${claimIds.length} claims but only ${rows.length} matched`,
        );
      }

      return rows;
    },

    // =========================================================================
    // Field Mapping Template Operations
    // =========================================================================

    /**
     * Insert a new field mapping template. Physician-scoped via data.physicianId.
     * Returns the created template with generated template_id.
     */
    async createTemplate(
      data: InsertFieldMappingTemplate,
    ): Promise<SelectFieldMappingTemplate> {
      const rows = await db
        .insert(fieldMappingTemplates)
        .values(data)
        .returning();
      return rows[0];
    },

    /**
     * Find a field mapping template by ID, scoped to physician.
     * Returns undefined if not found or belongs to a different physician.
     */
    async findTemplateById(
      templateId: string,
      physicianId: string,
    ): Promise<SelectFieldMappingTemplate | undefined> {
      const rows = await db
        .select()
        .from(fieldMappingTemplates)
        .where(
          and(
            eq(fieldMappingTemplates.templateId, templateId),
            eq(fieldMappingTemplates.physicianId, physicianId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * Update template fields. Sets updated_at to now().
     * Scoped to physician — returns undefined if not found or not owned.
     */
    async updateTemplate(
      templateId: string,
      physicianId: string,
      data: Partial<InsertFieldMappingTemplate>,
    ): Promise<SelectFieldMappingTemplate | undefined> {
      const rows = await db
        .update(fieldMappingTemplates)
        .set({ ...data, updatedAt: new Date() })
        .where(
          and(
            eq(fieldMappingTemplates.templateId, templateId),
            eq(fieldMappingTemplates.physicianId, physicianId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Hard delete a field mapping template. Templates are not PHI.
     * Verifies physician ownership before deletion.
     * Returns true if deleted, false if not found or not owned.
     */
    async deleteTemplate(
      templateId: string,
      physicianId: string,
    ): Promise<boolean> {
      const rows = await db
        .delete(fieldMappingTemplates)
        .where(
          and(
            eq(fieldMappingTemplates.templateId, templateId),
            eq(fieldMappingTemplates.physicianId, physicianId),
          ),
        )
        .returning();
      return rows.length > 0;
    },

    /**
     * List all field mapping templates for a physician.
     */
    async listTemplates(
      physicianId: string,
    ): Promise<SelectFieldMappingTemplate[]> {
      const rows = await db
        .select()
        .from(fieldMappingTemplates)
        .where(eq(fieldMappingTemplates.physicianId, physicianId))
        .orderBy(desc(fieldMappingTemplates.createdAt));
      return rows;
    },

    // =========================================================================
    // Shift Operations (ED Workflow)
    // =========================================================================

    /**
     * Insert a new shift with status = IN_PROGRESS.
     * Physician-scoped via data.physicianId.
     */
    async createShift(data: InsertShift): Promise<SelectShift> {
      const rows = await db
        .insert(shifts)
        .values({
          ...data,
          status: ShiftStatus.IN_PROGRESS,
        })
        .returning();
      return rows[0];
    },

    /**
     * Find a shift by ID, scoped to physician.
     * Returns undefined if not found or belongs to a different physician.
     */
    async findShiftById(
      shiftId: string,
      physicianId: string,
    ): Promise<SelectShift | undefined> {
      const rows = await db
        .select()
        .from(shifts)
        .where(
          and(
            eq(shifts.shiftId, shiftId),
            eq(shifts.physicianId, physicianId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * Update shift status. Physician-scoped.
     * Valid transitions: IN_PROGRESS -> COMPLETED -> SUBMITTED.
     */
    async updateShiftStatus(
      shiftId: string,
      physicianId: string,
      status: string,
    ): Promise<SelectShift | undefined> {
      const rows = await db
        .update(shifts)
        .set({ status, updatedAt: new Date() })
        .where(
          and(
            eq(shifts.shiftId, shiftId),
            eq(shifts.physicianId, physicianId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Update shift start and end times. Physician-scoped.
     * Used for after-hours premium calculation.
     */
    async updateShiftTimes(
      shiftId: string,
      physicianId: string,
      startTime: string,
      endTime: string,
    ): Promise<SelectShift | undefined> {
      const rows = await db
        .update(shifts)
        .set({ startTime, endTime, updatedAt: new Date() })
        .where(
          and(
            eq(shifts.shiftId, shiftId),
            eq(shifts.physicianId, physicianId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Increment encounter_count by 1. Physician-scoped.
     */
    async incrementEncounterCount(
      shiftId: string,
      physicianId: string,
    ): Promise<SelectShift | undefined> {
      const rows = await db
        .update(shifts)
        .set({
          encounterCount: sql`${shifts.encounterCount} + 1`,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(shifts.shiftId, shiftId),
            eq(shifts.physicianId, physicianId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Paginated list of shifts, reverse chronological by shift_date.
     * Physician-scoped.
     */
    async listShifts(
      physicianId: string,
      page: number,
      pageSize: number,
    ): Promise<PaginatedResult<SelectShift>> {
      const whereClause = eq(shifts.physicianId, physicianId);
      const offset = (page - 1) * pageSize;

      const [countResult, rows] = await Promise.all([
        db
          .select({ total: count() })
          .from(shifts)
          .where(whereClause),
        db
          .select()
          .from(shifts)
          .where(whereClause)
          .orderBy(desc(shifts.shiftDate))
          .limit(pageSize)
          .offset(offset),
      ]);

      const total = Number(countResult[0]?.total ?? 0);

      return {
        data: rows,
        pagination: {
          total,
          page,
          pageSize,
          hasMore: page * pageSize < total,
        },
      };
    },

    /**
     * Find all claims linked to a specific shift.
     * Physician-scoped. Excludes soft-deleted claims.
     */
    async findClaimsByShift(
      shiftId: string,
      physicianId: string,
    ): Promise<SelectClaim[]> {
      const rows = await db
        .select()
        .from(claims)
        .where(
          and(
            eq(claims.shiftId, shiftId),
            eq(claims.physicianId, physicianId),
            isNull(claims.deletedAt),
          ),
        )
        .orderBy(claims.createdAt);
      return rows;
    },

    // =========================================================================
    // Data Export Records
    // =========================================================================

    /**
     * Insert a new export record with PENDING status.
     * Physician-scoped via data.physicianId.
     * Returns the created record with generated export_id.
     */
    async createExportRecord(data: {
      physicianId: string;
      dateFrom: string;
      dateTo: string;
      claimType?: string;
      format: string;
      status?: string;
    }): Promise<SelectClaimExport> {
      const rows = await db
        .insert(claimExports)
        .values({
          ...data,
          status: ExportStatus.PENDING,
        } as InsertClaimExport)
        .returning();
      return rows[0];
    },

    /**
     * Find an export record by ID, scoped to physician.
     * Returns undefined if not found or belongs to a different physician.
     */
    async findExportById(
      exportId: string,
      physicianId: string,
    ): Promise<SelectClaimExport | undefined> {
      const rows = await db
        .select()
        .from(claimExports)
        .where(
          and(
            eq(claimExports.exportId, exportId),
            eq(claimExports.physicianId, physicianId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * Update export status and optional file path.
     * Used to transition: PENDING → PROCESSING → COMPLETED (with filePath) or FAILED.
     * Physician-scoped.
     */
    async updateExportStatus(
      exportId: string,
      physicianId: string,
      status: string,
      filePath?: string,
    ): Promise<SelectClaimExport | undefined> {
      const setClauses: Record<string, unknown> = {
        status,
        updatedAt: new Date(),
      };
      if (filePath !== undefined) {
        setClauses.filePath = filePath;
      }

      const rows = await db
        .update(claimExports)
        .set(setClauses)
        .where(
          and(
            eq(claimExports.exportId, exportId),
            eq(claimExports.physicianId, physicianId),
          ),
        )
        .returning();
      return rows[0];
    },

    // =========================================================================
    // Claim Audit History (Append-Only)
    // =========================================================================

    /**
     * Append an audit entry to claim_audit_history.
     * This is the ONLY write operation on claim_audit_history.
     * No update or delete functions exist — the table is append-only.
     */
    async appendClaimAudit(
      entry: InsertClaimAuditHistory,
    ): Promise<SelectClaimAuditHistory> {
      const rows = await db
        .insert(claimAuditHistory)
        .values(entry)
        .returning();
      return rows[0];
    },

    /**
     * Return all audit entries for a claim, reverse chronological.
     * Verifies claim belongs to physician before returning entries.
     * Returns empty array if claim not found or belongs to different physician.
     */
    async getClaimAuditHistory(
      claimId: string,
      physicianId: string,
    ): Promise<SelectClaimAuditHistory[]> {
      // Verify claim ownership first
      const claim = await db
        .select()
        .from(claims)
        .where(
          and(
            eq(claims.claimId, claimId),
            eq(claims.physicianId, physicianId),
          ),
        )
        .limit(1);

      if (claim.length === 0) {
        return [];
      }

      const rows = await db
        .select()
        .from(claimAuditHistory)
        .where(eq(claimAuditHistory.claimId, claimId))
        .orderBy(desc(claimAuditHistory.createdAt));

      return rows;
    },

    /**
     * Paginated version of getClaimAuditHistory.
     * Verifies claim belongs to physician before returning entries.
     * Returns empty result if claim not found or belongs to different physician.
     */
    async getClaimAuditHistoryPaginated(
      claimId: string,
      physicianId: string,
      page: number,
      pageSize: number,
    ): Promise<PaginatedResult<SelectClaimAuditHistory>> {
      // Verify claim ownership first
      const claim = await db
        .select()
        .from(claims)
        .where(
          and(
            eq(claims.claimId, claimId),
            eq(claims.physicianId, physicianId),
          ),
        )
        .limit(1);

      if (claim.length === 0) {
        return {
          data: [],
          pagination: { total: 0, page, pageSize, hasMore: false },
        };
      }

      const whereClause = eq(claimAuditHistory.claimId, claimId);
      const offset = (page - 1) * pageSize;

      const [countResult, rows] = await Promise.all([
        db
          .select({ total: count() })
          .from(claimAuditHistory)
          .where(whereClause),
        db
          .select()
          .from(claimAuditHistory)
          .where(whereClause)
          .orderBy(desc(claimAuditHistory.createdAt))
          .limit(pageSize)
          .offset(offset),
      ]);

      const total = Number(countResult[0]?.total ?? 0);

      return {
        data: rows,
        pagination: {
          total,
          page,
          pageSize,
          hasMore: page * pageSize < total,
        },
      };
    },
  };
}

export type ClaimRepository = ReturnType<typeof createClaimRepository>;
