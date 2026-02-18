import { eq, and, sql, desc, count, isNotNull, ilike, or } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  patients,
  patientImportBatches,
  patientMergeHistory,
  type InsertPatient,
  type SelectPatient,
  type InsertPatientImportBatch,
  type SelectPatientImportBatch,
  type SelectPatientMergeHistory,
} from '@meritum/shared/schemas/db/patient.schema.js';
import { validateAlbertaPhn } from '@meritum/shared/utils/phn.utils.js';

// ---------------------------------------------------------------------------
// Pagination types
// ---------------------------------------------------------------------------

export interface PaginatedResult<T> {
  data: T[];
  pagination: {
    total: number;
    page: number;
    pageSize: number;
    hasMore: boolean;
  };
}

// ---------------------------------------------------------------------------
// Patient Repository
// ---------------------------------------------------------------------------

export function createPatientRepository(db: NodePgDatabase) {
  return {
    /**
     * Insert a new patient record.
     * PHN uniqueness within a physician is enforced by the partial unique
     * index (provider_id, phn) WHERE phn IS NOT NULL.
     */
    async createPatient(data: InsertPatient): Promise<SelectPatient> {
      const rows = await db
        .insert(patients)
        .values(data)
        .returning();
      return rows[0];
    },

    /**
     * Find a patient by ID, scoped to physician.
     * Returns undefined if not found or belongs to a different physician.
     */
    async findPatientById(
      patientId: string,
      physicianId: string,
    ): Promise<SelectPatient | undefined> {
      const rows = await db
        .select()
        .from(patients)
        .where(
          and(
            eq(patients.patientId, patientId),
            eq(patients.providerId, physicianId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * Find a patient by PHN, scoped to physician.
     * Exact match on (provider_id, phn). Used for duplicate check and
     * import matching.
     */
    async findPatientByPhn(
      physicianId: string,
      phn: string,
    ): Promise<SelectPatient | undefined> {
      const rows = await db
        .select()
        .from(patients)
        .where(
          and(
            eq(patients.providerId, physicianId),
            eq(patients.phn, phn),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * Update patient fields. Sets updated_at to now().
     * Scoped to physician — returns undefined if not found or not owned.
     */
    async updatePatient(
      patientId: string,
      physicianId: string,
      data: Partial<InsertPatient>,
    ): Promise<SelectPatient | undefined> {
      const rows = await db
        .update(patients)
        .set({ ...data, updatedAt: new Date() })
        .where(
          and(
            eq(patients.patientId, patientId),
            eq(patients.providerId, physicianId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Soft-delete: set is_active = false.
     * Scoped to physician — returns undefined if not found or not owned.
     */
    async deactivatePatient(
      patientId: string,
      physicianId: string,
    ): Promise<SelectPatient | undefined> {
      const rows = await db
        .update(patients)
        .set({ isActive: false, updatedAt: new Date() })
        .where(
          and(
            eq(patients.patientId, patientId),
            eq(patients.providerId, physicianId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Re-activate a soft-deleted patient: set is_active = true.
     * Scoped to physician — returns undefined if not found or not owned.
     */
    async reactivatePatient(
      patientId: string,
      physicianId: string,
    ): Promise<SelectPatient | undefined> {
      const rows = await db
        .update(patients)
        .set({ isActive: true, updatedAt: new Date() })
        .where(
          and(
            eq(patients.patientId, patientId),
            eq(patients.providerId, physicianId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Update last_visit_date. Called when a claim is created for this patient.
     * Scoped to physician — returns undefined if not found or not owned.
     */
    async updateLastVisitDate(
      patientId: string,
      physicianId: string,
      date: Date,
    ): Promise<SelectPatient | undefined> {
      const dateStr = date.toISOString().split('T')[0];
      const rows = await db
        .update(patients)
        .set({ lastVisitDate: dateStr, updatedAt: new Date() })
        .where(
          and(
            eq(patients.patientId, patientId),
            eq(patients.providerId, physicianId),
          ),
        )
        .returning();
      return rows[0];
    },

    // =========================================================================
    // Search functions
    // =========================================================================

    /**
     * Search by PHN — exact match on (physician_id, phn) where is_active = true.
     * Returns 0 or 1 result.
     */
    async searchByPhn(
      physicianId: string,
      phn: string,
    ): Promise<SelectPatient | undefined> {
      const rows = await db
        .select()
        .from(patients)
        .where(
          and(
            eq(patients.providerId, physicianId),
            eq(patients.phn, phn),
            eq(patients.isActive, true),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * Search by name — case-insensitive prefix match using ILIKE.
     * Uses pg_trgm similarity for ranking. Minimum 2 characters required.
     * Only active patients. Paginated.
     */
    async searchByName(
      physicianId: string,
      nameQuery: string,
      page: number,
      pageSize: number,
    ): Promise<PaginatedResult<SelectPatient>> {
      if (nameQuery.length < 2) {
        return { data: [], pagination: { total: 0, page, pageSize, hasMore: false } };
      }

      const pattern = `%${nameQuery}%`;
      const offset = (page - 1) * pageSize;

      const whereClause = and(
        eq(patients.providerId, physicianId),
        eq(patients.isActive, true),
        or(
          ilike(patients.firstName, pattern),
          ilike(patients.lastName, pattern),
        ),
      );

      const [countResult, rows] = await Promise.all([
        db
          .select({ total: count() })
          .from(patients)
          .where(whereClause!),
        db
          .select()
          .from(patients)
          .where(whereClause!)
          .orderBy(
            desc(
              sql`similarity(${patients.lastName} || ' ' || ${patients.firstName}, ${nameQuery})`,
            ),
          )
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
     * Search by date of birth — exact match. Only active patients. Paginated.
     */
    async searchByDob(
      physicianId: string,
      dob: Date,
      page: number,
      pageSize: number,
    ): Promise<PaginatedResult<SelectPatient>> {
      const dobStr = dob.toISOString().split('T')[0];
      const offset = (page - 1) * pageSize;

      const whereClause = and(
        eq(patients.providerId, physicianId),
        eq(patients.isActive, true),
        eq(patients.dateOfBirth, dobStr),
      );

      const [countResult, rows] = await Promise.all([
        db
          .select({ total: count() })
          .from(patients)
          .where(whereClause!),
        db
          .select()
          .from(patients)
          .where(whereClause!)
          .orderBy(patients.lastName, patients.firstName)
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
     * Combined search — AND all provided criteria.
     * Only active patients. Paginated.
     */
    async searchCombined(
      physicianId: string,
      filters: { phn?: string; name?: string; dob?: Date },
      page: number,
      pageSize: number,
    ): Promise<PaginatedResult<SelectPatient>> {
      const conditions = [
        eq(patients.providerId, physicianId),
        eq(patients.isActive, true),
      ];

      if (filters.phn) {
        conditions.push(eq(patients.phn, filters.phn));
      }

      if (filters.name && filters.name.length >= 2) {
        const pattern = `%${filters.name}%`;
        conditions.push(
          or(
            ilike(patients.firstName, pattern),
            ilike(patients.lastName, pattern),
          )!,
        );
      }

      if (filters.dob) {
        const dobStr = filters.dob.toISOString().split('T')[0];
        conditions.push(eq(patients.dateOfBirth, dobStr));
      }

      const whereClause = and(...conditions);
      const offset = (page - 1) * pageSize;

      const [countResult, rows] = await Promise.all([
        db
          .select({ total: count() })
          .from(patients)
          .where(whereClause!),
        db
          .select()
          .from(patients)
          .where(whereClause!)
          .orderBy(patients.lastName, patients.firstName)
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
     * Get recent patients — ordered by last_visit_date DESC.
     * Only active patients with a non-null last_visit_date.
     */
    async getRecentPatients(
      physicianId: string,
      limit: number = 20,
    ): Promise<SelectPatient[]> {
      const rows = await db
        .select()
        .from(patients)
        .where(
          and(
            eq(patients.providerId, physicianId),
            eq(patients.isActive, true),
            isNotNull(patients.lastVisitDate),
          ),
        )
        .orderBy(desc(patients.lastVisitDate))
        .limit(limit);
      return rows;
    },

    // =========================================================================
    // CSV Import Batch Operations
    // =========================================================================

    /**
     * Insert an import batch record with PENDING status.
     * Scoped to physician via physicianId in the data.
     */
    async createImportBatch(
      data: InsertPatientImportBatch,
    ): Promise<SelectPatientImportBatch> {
      const rows = await db
        .insert(patientImportBatches)
        .values(data)
        .returning();
      return rows[0];
    },

    /**
     * Find an import batch by ID, scoped to physician.
     * Returns undefined if not found or belongs to a different physician.
     */
    async findImportBatchById(
      importId: string,
      physicianId: string,
    ): Promise<SelectPatientImportBatch | undefined> {
      const rows = await db
        .select()
        .from(patientImportBatches)
        .where(
          and(
            eq(patientImportBatches.importId, importId),
            eq(patientImportBatches.physicianId, physicianId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * Check for duplicate file upload by SHA-256 hash, scoped to physician.
     * Returns the existing import batch if found, undefined otherwise.
     */
    async findImportByFileHash(
      physicianId: string,
      fileHash: string,
    ): Promise<SelectPatientImportBatch | undefined> {
      const rows = await db
        .select()
        .from(patientImportBatches)
        .where(
          and(
            eq(patientImportBatches.physicianId, physicianId),
            eq(patientImportBatches.fileHash, fileHash),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * Update import batch status and result counts.
     * Scoped to physician via importId lookup.
     */
    async updateImportStatus(
      importId: string,
      status: string,
      counts?: { created: number; updated: number; skipped: number; error: number },
      errorDetails?: unknown,
    ): Promise<SelectPatientImportBatch | undefined> {
      const setClauses: Record<string, unknown> = { status };
      if (counts) {
        setClauses.createdCount = counts.created;
        setClauses.updatedCount = counts.updated;
        setClauses.skippedCount = counts.skipped;
        setClauses.errorCount = counts.error;
      }
      if (errorDetails !== undefined) {
        setClauses.errorDetails = errorDetails;
      }
      const rows = await db
        .update(patientImportBatches)
        .set(setClauses)
        .where(eq(patientImportBatches.importId, importId))
        .returning();
      return rows[0];
    },

    /**
     * List import batches for a physician, newest first. Paginated.
     */
    async listImportBatches(
      physicianId: string,
      page: number,
      pageSize: number,
    ): Promise<PaginatedResult<SelectPatientImportBatch>> {
      const offset = (page - 1) * pageSize;

      const whereClause = eq(patientImportBatches.physicianId, physicianId);

      const [countResult, rows] = await Promise.all([
        db
          .select({ total: count() })
          .from(patientImportBatches)
          .where(whereClause),
        db
          .select()
          .from(patientImportBatches)
          .where(whereClause)
          .orderBy(desc(patientImportBatches.createdAt))
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
     * Batch insert multiple patients in a single transaction.
     * Returns array of created patient_ids.
     * All-or-nothing: rolls back on any failure.
     */
    async bulkCreatePatients(
      physicianId: string,
      patientsData: InsertPatient[],
    ): Promise<string[]> {
      return db.transaction(async (tx) => {
        const stamped = patientsData.map((p) => ({
          ...p,
          providerId: physicianId,
        }));
        const rows = await tx
          .insert(patients)
          .values(stamped)
          .returning();
        return rows.map((r) => r.patientId);
      });
    },

    /**
     * Upsert patients by PHN match within a physician's roster.
     * For rows with PHN match: update. For rows without match: insert.
     * Runs in a transaction — all-or-nothing.
     * Returns counts of created and updated records.
     */
    async bulkUpsertPatients(
      physicianId: string,
      patientsData: { phn: string; data: Partial<InsertPatient> }[],
    ): Promise<{ created: number; updated: number }> {
      return db.transaction(async (tx) => {
        let created = 0;
        let updated = 0;

        for (const item of patientsData) {
          const existing = await tx
            .select()
            .from(patients)
            .where(
              and(
                eq(patients.providerId, physicianId),
                eq(patients.phn, item.phn),
              ),
            )
            .limit(1);

          if (existing.length > 0) {
            await tx
              .update(patients)
              .set({ ...item.data, updatedAt: new Date() })
              .where(
                and(
                  eq(patients.providerId, physicianId),
                  eq(patients.phn, item.phn),
                ),
              );
            updated++;
          } else {
            await tx
              .insert(patients)
              .values({
                ...item.data,
                phn: item.phn,
                providerId: physicianId,
              } as InsertPatient);
            created++;
          }
        }

        return { created, updated };
      });
    },

    // =========================================================================
    // Patient Merge Operations
    // =========================================================================

    /**
     * Return side-by-side comparison of both patient records plus count
     * of draft/validated claims that would be transferred.
     * Both patients must belong to the physician.
     */
    async getMergePreview(
      physicianId: string,
      survivingId: string,
      mergedId: string,
    ): Promise<{
      surviving: SelectPatient;
      merged: SelectPatient;
      claimsToTransfer: number;
      fieldConflicts: Record<string, { surviving: unknown; merged: unknown }>;
    } | null> {
      const [survivingRows, mergedRows] = await Promise.all([
        db
          .select()
          .from(patients)
          .where(
            and(
              eq(patients.patientId, survivingId),
              eq(patients.providerId, physicianId),
              eq(patients.isActive, true),
            ),
          )
          .limit(1),
        db
          .select()
          .from(patients)
          .where(
            and(
              eq(patients.patientId, mergedId),
              eq(patients.providerId, physicianId),
              eq(patients.isActive, true),
            ),
          )
          .limit(1),
      ]);

      const surviving = survivingRows[0];
      const merged = mergedRows[0];

      if (!surviving || !merged) {
        return null;
      }

      // Count draft/validated claims that would be transferred
      const claimCountResult = await db.execute(
        sql`SELECT COUNT(*)::int AS count FROM claims
            WHERE patient_id = ${mergedId}
            AND provider_id = ${physicianId}
            AND status IN ('draft', 'validated')`,
      );
      const claimsToTransfer = (claimCountResult as any).rows?.[0]?.count ?? 0;

      // Compute field conflicts (fields where values differ)
      const compareFields = [
        'phn', 'phnProvince', 'firstName', 'middleName', 'lastName',
        'dateOfBirth', 'gender', 'phone', 'email',
        'addressLine1', 'addressLine2', 'city', 'province', 'postalCode',
        'notes',
      ] as const;

      const fieldConflicts: Record<string, { surviving: unknown; merged: unknown }> = {};
      for (const field of compareFields) {
        const sVal = surviving[field];
        const mVal = merged[field];
        if (sVal !== mVal) {
          fieldConflicts[field] = { surviving: sVal, merged: mVal };
        }
      }

      return { surviving, merged, claimsToTransfer, fieldConflicts };
    },

    /**
     * Execute a patient merge in a single transaction:
     * 1. Transfer draft/validated claims from merged patient to surviving patient
     * 2. Soft-delete the merged patient (is_active = false)
     * 3. Record in patient_merge_history
     *
     * Only draft/validated claims have patient_id updated.
     * Submitted/assessed/paid claims retain original patient_id (audit integrity).
     * Both patients must belong to the physician.
     */
    async executeMerge(
      physicianId: string,
      survivingId: string,
      mergedId: string,
      mergedBy: string,
    ): Promise<{
      mergeId: string;
      claimsTransferred: number;
      fieldConflicts: Record<string, { surviving: unknown; merged: unknown }>;
    } | null> {
      return db.transaction(async (tx) => {
        // Verify both patients belong to this physician and are active
        const [survivingRows, mergedRows] = await Promise.all([
          tx
            .select()
            .from(patients)
            .where(
              and(
                eq(patients.patientId, survivingId),
                eq(patients.providerId, physicianId),
                eq(patients.isActive, true),
              ),
            )
            .limit(1),
          tx
            .select()
            .from(patients)
            .where(
              and(
                eq(patients.patientId, mergedId),
                eq(patients.providerId, physicianId),
                eq(patients.isActive, true),
              ),
            )
            .limit(1),
        ]);

        const surviving = survivingRows[0];
        const merged = mergedRows[0];

        if (!surviving || !merged) {
          return null;
        }

        // 1. Transfer draft/validated claims from merged → surviving
        const transferResult = await tx.execute(
          sql`UPDATE claims
              SET patient_id = ${survivingId}, updated_at = NOW()
              WHERE patient_id = ${mergedId}
              AND provider_id = ${physicianId}
              AND status IN ('draft', 'validated')`,
        );
        const claimsTransferred = (transferResult as any).rowCount ?? 0;

        // 2. Soft-delete merged patient
        await tx
          .update(patients)
          .set({ isActive: false, updatedAt: new Date() })
          .where(
            and(
              eq(patients.patientId, mergedId),
              eq(patients.providerId, physicianId),
            ),
          );

        // 3. Compute field conflicts
        const compareFields = [
          'phn', 'phnProvince', 'firstName', 'middleName', 'lastName',
          'dateOfBirth', 'gender', 'phone', 'email',
          'addressLine1', 'addressLine2', 'city', 'province', 'postalCode',
          'notes',
        ] as const;

        const fieldConflicts: Record<string, { surviving: unknown; merged: unknown }> = {};
        for (const field of compareFields) {
          const sVal = surviving[field];
          const mVal = merged[field];
          if (sVal !== mVal) {
            fieldConflicts[field] = { surviving: sVal, merged: mVal };
          }
        }

        // 4. Record merge history
        const mergeRows = await tx
          .insert(patientMergeHistory)
          .values({
            physicianId,
            survivingPatientId: survivingId,
            mergedPatientId: mergedId,
            claimsTransferred,
            fieldConflicts,
            mergedBy,
          })
          .returning();

        return {
          mergeId: mergeRows[0].mergeId,
          claimsTransferred,
          fieldConflicts,
        };
      });
    },

    /**
     * List merge history for physician, newest first. Paginated.
     */
    async listMergeHistory(
      physicianId: string,
      page: number,
      pageSize: number,
    ): Promise<PaginatedResult<SelectPatientMergeHistory>> {
      const offset = (page - 1) * pageSize;

      const whereClause = eq(patientMergeHistory.physicianId, physicianId);

      const [countResult, rows] = await Promise.all([
        db
          .select({ total: count() })
          .from(patientMergeHistory)
          .where(whereClause),
        db
          .select()
          .from(patientMergeHistory)
          .where(whereClause)
          .orderBy(desc(patientMergeHistory.mergedAt))
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

    // =========================================================================
    // Export Operations
    // =========================================================================

    /**
     * Return all active patients for CSV export.
     * Selects demographic and address fields only — notes are excluded
     * (physician's private clinical observations, never exported).
     * Scoped to physician.
     */
    async exportActivePatients(
      physicianId: string,
    ): Promise<PatientExportRow[]> {
      const rows = await db
        .select({
          phn: patients.phn,
          firstName: patients.firstName,
          lastName: patients.lastName,
          dateOfBirth: patients.dateOfBirth,
          gender: patients.gender,
          phone: patients.phone,
          addressLine1: patients.addressLine1,
          addressLine2: patients.addressLine2,
          city: patients.city,
          province: patients.province,
          postalCode: patients.postalCode,
        })
        .from(patients)
        .where(
          and(
            eq(patients.providerId, physicianId),
            eq(patients.isActive, true),
          ),
        )
        .orderBy(patients.lastName, patients.firstName);
      return rows;
    },

    /**
     * Count active patients for export metadata.
     * Scoped to physician.
     */
    async countActivePatients(physicianId: string): Promise<number> {
      const result = await db
        .select({ total: count() })
        .from(patients)
        .where(
          and(
            eq(patients.providerId, physicianId),
            eq(patients.isActive, true),
          ),
        );
      return Number(result[0]?.total ?? 0);
    },

    // =========================================================================
    // Internal API (consumed by Domain 4)
    // =========================================================================

    /**
     * Return minimal patient payload for claim creation.
     * Only fields required by the claim form — no notes, no address, no phone.
     * Scoped to physician.
     */
    async getPatientClaimContext(
      patientId: string,
      physicianId: string,
    ): Promise<PatientClaimContext | null> {
      const rows = await db
        .select({
          patientId: patients.patientId,
          phn: patients.phn,
          phnProvince: patients.phnProvince,
          firstName: patients.firstName,
          lastName: patients.lastName,
          dateOfBirth: patients.dateOfBirth,
          gender: patients.gender,
        })
        .from(patients)
        .where(
          and(
            eq(patients.patientId, patientId),
            eq(patients.providerId, physicianId),
            eq(patients.isActive, true),
          ),
        )
        .limit(1);
      return rows[0] ?? null;
    },

    /**
     * Validate PHN format (Luhn) and check if a patient with this PHN
     * exists in the physician's registry.
     * Scoped to physician — cannot check other physicians' patient lists.
     */
    async validatePhnExists(
      physicianId: string,
      phn: string,
    ): Promise<{ valid: boolean; exists: boolean; patientId?: string }> {
      const luhn = validateAlbertaPhn(phn);
      if (!luhn.valid) {
        return { valid: false, exists: false };
      }

      const rows = await db
        .select({
          patientId: patients.patientId,
        })
        .from(patients)
        .where(
          and(
            eq(patients.providerId, physicianId),
            eq(patients.phn, phn),
            eq(patients.isActive, true),
          ),
        )
        .limit(1);

      if (rows[0]) {
        return { valid: true, exists: true, patientId: rows[0].patientId };
      }
      return { valid: true, exists: false };
    },
  };
}

// ---------------------------------------------------------------------------
// Export types
// ---------------------------------------------------------------------------

export interface PatientExportRow {
  phn: string | null;
  firstName: string;
  lastName: string;
  dateOfBirth: string;
  gender: string;
  phone: string | null;
  addressLine1: string | null;
  addressLine2: string | null;
  city: string | null;
  province: string | null;
  postalCode: string | null;
}

export interface PatientClaimContext {
  patientId: string;
  phn: string | null;
  phnProvince: string | null;
  firstName: string;
  lastName: string;
  dateOfBirth: string;
  gender: string;
}

export type PatientRepository = ReturnType<typeof createPatientRepository>;
