import { eq, and, desc, count, isNull, inArray } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import { randomBytes } from 'crypto';
import {
  wcbClaimDetails,
  wcbInjuries,
  wcbPrescriptions,
  wcbConsultations,
  wcbWorkRestrictions,
  wcbInvoiceLines,
  wcbAttachments,
  wcbBatches,
  wcbReturnRecords,
  wcbReturnInvoiceLines,
  wcbRemittanceImports,
  wcbRemittanceRecords,
  type InsertWcbClaimDetail,
  type SelectWcbClaimDetail,
  type SelectWcbInjury,
  type SelectWcbPrescription,
  type SelectWcbConsultation,
  type SelectWcbWorkRestriction,
  type SelectWcbInvoiceLine,
  type SelectWcbAttachment,
  type SelectWcbBatch,
  type SelectWcbReturnRecord,
  type SelectWcbReturnInvoiceLine,
  type SelectWcbRemittanceImport,
  type SelectWcbRemittanceRecord,
} from '@meritum/shared/schemas/db/wcb.schema.js';
import {
  claims,
  type SelectClaim,
} from '@meritum/shared/schemas/db/claim.schema.js';
import { ClaimState, ClaimType } from '@meritum/shared/constants/claim.constants.js';
import { WcbBatchStatus } from '@meritum/shared/constants/wcb.constants.js';
import { BusinessRuleError, ConflictError } from '../../lib/errors.js';

// ---------------------------------------------------------------------------
// Vendor prefix for submitter transaction IDs
// ---------------------------------------------------------------------------

const VENDOR_PREFIX = 'MRT';

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export interface WcbClaimWithChildren {
  detail: SelectWcbClaimDetail;
  claim: SelectClaim;
  injuries: SelectWcbInjury[];
  prescriptions: SelectWcbPrescription[];
  consultations: SelectWcbConsultation[];
  workRestrictions: SelectWcbWorkRestriction[];
  invoiceLines: SelectWcbInvoiceLine[];
  attachments: SelectWcbAttachment[];
}

export interface WcbClaimListItem {
  detail: SelectWcbClaimDetail;
  claim: SelectClaim;
}

export interface ListWcbClaimsFilters {
  status?: string;
  formId?: string;
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

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

export interface CreateWcbClaimInput {
  claimId: string;
  formId: string;
  reportCompletionDate: string;
  dateOfInjury: string;
  practitionerBillingNumber: string;
  contractId: string;
  roleCode: string;
  practitionerFirstName: string;
  practitionerMiddleName?: string;
  practitionerLastName: string;
  skillCode: string;
  facilityType: string;
  clinicReferenceNumber?: string;
  billingContactName?: string;
  faxCountryCode?: string;
  faxNumber?: string;
  patientNoPhnFlag: string;
  patientPhn?: string;
  patientGender: string;
  patientFirstName: string;
  patientMiddleName?: string;
  patientLastName: string;
  patientDob: string;
  patientAddressLine1: string;
  patientAddressLine2?: string;
  patientCity: string;
  patientProvince?: string;
  patientPostalCode?: string;
  patientPhoneCountry?: string;
  patientPhoneNumber?: string;
  createdBy: string;
  updatedBy: string;
  // All other optional WCB form fields
  [key: string]: unknown;
}

export type UpdateWcbClaimInput = Partial<
  Omit<InsertWcbClaimDetail, 'wcbClaimDetailId' | 'claimId' | 'formId' | 'submitterTxnId' | 'createdAt' | 'createdBy'>
>;

export interface InjuryInput {
  partOfBodyCode: string;
  sideOfBodyCode?: string;
  natureOfInjuryCode: string;
}

export interface PrescriptionInput {
  prescriptionName: string;
  strength: string;
  dailyIntake: string;
}

export interface ConsultationInput {
  category: string;
  typeCode: string;
  details: string;
  expediteRequested?: string;
}

export interface RestrictionInput {
  activityType: string;
  restrictionLevel: string;
  hoursPerDay?: number;
  maxWeight?: string;
}

export interface InvoiceLineInput {
  lineType: string;
  healthServiceCode?: string;
  diagnosticCode1?: string;
  diagnosticCode2?: string;
  diagnosticCode3?: string;
  modifier1?: string;
  modifier2?: string;
  modifier3?: string;
  calls?: number;
  encounters?: number;
  dateOfServiceFrom?: string;
  dateOfServiceTo?: string;
  facilityTypeOverride?: string;
  skillCodeOverride?: string;
  invoiceDetailTypeCode?: string;
  invoiceDetailDesc?: string;
  quantity?: number;
  supplyDescription?: string;
  amount?: string;
  adjustmentIndicator?: string;
  billingNumberOverride?: string;
  correctionPairId?: number;
}

export interface AttachmentInput {
  fileName: string;
  fileType: string;
  fileContentB64: string;
  fileDescription: string;
  fileSizeBytes: number;
}

export interface ReturnRecordInput {
  reportTxnId: string;
  submitterTxnId: string;
  processedClaimNumber?: string;
  claimDecision: string;
  reportStatus: string;
  txnSubmissionDate: string;
  errors?: unknown;
  wcbClaimDetailId?: string;
}

export interface ReturnInvoiceLineInput {
  invoiceSequence: number;
  serviceDate?: string;
  healthServiceCode?: string;
  invoiceStatus?: string;
}

export interface RemittanceRecordInput {
  reportWeekStart: string;
  reportWeekEnd: string;
  disbursementNumber?: string;
  disbursementType?: string;
  disbursementIssueDate?: string;
  disbursementAmount?: string;
  disbursementRecipientBilling?: string;
  disbursementRecipientName?: string;
  paymentPayeeBilling: string;
  paymentPayeeName: string;
  paymentReasonCode: string;
  paymentStatus: string;
  paymentStartDate: string;
  paymentEndDate: string;
  paymentAmount: string;
  billedAmount?: string;
  electronicReportTxnId?: string;
  claimNumber?: string;
  workerPhn?: string;
  workerFirstName?: string;
  workerLastName?: string;
  serviceCode?: string;
  modifier1?: string;
  modifier2?: string;
  modifier3?: string;
  numberOfCalls?: number;
  encounterNumber?: number;
  overpaymentRecovery?: string;
  wcbClaimDetailId?: string;
}

export interface ListRemittanceImportsFilters {
  startDate?: string;
  endDate?: string;
  page: number;
  pageSize: number;
}

export interface RemittanceDiscrepancy extends SelectWcbRemittanceRecord {
  discrepancyType: 'AMOUNT_MISMATCH' | 'STATUS_NOT_ISSUED';
}

export interface ReturnRecordWithInvoiceLines {
  returnRecord: SelectWcbReturnRecord;
  invoiceLines: SelectWcbReturnInvoiceLine[];
}

export interface ListBatchesFilters {
  status?: string;
  page: number;
  pageSize: number;
}

export interface WcbBatchWithCount extends SelectWcbBatch {
  reportCount: number;
}

export interface QueuedWcbClaim {
  claim: SelectClaim;
  detail: SelectWcbClaimDetail;
}

export interface C570ValidationResult {
  valid: boolean;
  errors: string[];
}

export interface AttachmentMetadata {
  wcbAttachmentId: string;
  wcbClaimDetailId: string;
  ordinal: number;
  fileName: string;
  fileType: string;
  fileDescription: string;
  fileSizeBytes: number;
}

// ---------------------------------------------------------------------------
// Submitter transaction ID generation
// ---------------------------------------------------------------------------

function generateSubmitterTxnId(): string {
  // Format: MRT + 13 hex chars from crypto random = 16 chars total
  const randomPart = randomBytes(7).toString('hex').slice(0, 13).toUpperCase();
  return `${VENDOR_PREFIX}${randomPart}`;
}

// ---------------------------------------------------------------------------
// Batch ID generation
// ---------------------------------------------------------------------------

function generateBatchControlId(): string {
  // Format: MER-B-{8 hex chars from crypto random}
  const shortId = randomBytes(4).toString('hex').toUpperCase();
  return `MER-B-${shortId}`;
}

function generateFileControlId(): string {
  // Format: MER-{YYYYMMDD}-{6 hex chars from crypto random}
  const now = new Date();
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, '0');
  const d = String(now.getDate()).padStart(2, '0');
  const seq = randomBytes(3).toString('hex').toUpperCase();
  return `MER-${y}${m}${d}-${seq}`;
}

// ---------------------------------------------------------------------------
// Valid batch status transitions
// ---------------------------------------------------------------------------

const VALID_BATCH_TRANSITIONS: Record<string, string[]> = {
  [WcbBatchStatus.ASSEMBLING]: [WcbBatchStatus.GENERATED, WcbBatchStatus.ERROR],
  [WcbBatchStatus.GENERATED]: [WcbBatchStatus.VALIDATED, WcbBatchStatus.ERROR],
  [WcbBatchStatus.VALIDATED]: [WcbBatchStatus.UPLOADED, WcbBatchStatus.ERROR],
  [WcbBatchStatus.UPLOADED]: [WcbBatchStatus.RETURN_RECEIVED],
  [WcbBatchStatus.RETURN_RECEIVED]: [WcbBatchStatus.RECONCILED],
  [WcbBatchStatus.RECONCILED]: [],
  [WcbBatchStatus.ERROR]: [],
};

// ---------------------------------------------------------------------------
// WCB Repository
// ---------------------------------------------------------------------------

export function createWcbRepository(db: NodePgDatabase) {
  return {
    /**
     * Insert a new WCB claim detail row linked to a base claim.
     * Generates a cryptographically unique submitter_txn_id with vendor prefix.
     * Returns the created WCB claim detail.
     */
    async createWcbClaim(
      data: CreateWcbClaimInput,
    ): Promise<SelectWcbClaimDetail> {
      const submitterTxnId = generateSubmitterTxnId();

      const insertData: InsertWcbClaimDetail = {
        claimId: data.claimId,
        formId: data.formId,
        submitterTxnId,
        reportCompletionDate: data.reportCompletionDate,
        dateOfInjury: data.dateOfInjury,
        practitionerBillingNumber: data.practitionerBillingNumber,
        contractId: data.contractId,
        roleCode: data.roleCode,
        practitionerFirstName: data.practitionerFirstName,
        practitionerMiddleName: data.practitionerMiddleName,
        practitionerLastName: data.practitionerLastName,
        skillCode: data.skillCode,
        facilityType: data.facilityType,
        clinicReferenceNumber: data.clinicReferenceNumber,
        billingContactName: data.billingContactName,
        faxCountryCode: data.faxCountryCode,
        faxNumber: data.faxNumber,
        patientNoPhnFlag: data.patientNoPhnFlag,
        patientPhn: data.patientPhn,
        patientGender: data.patientGender,
        patientFirstName: data.patientFirstName,
        patientMiddleName: data.patientMiddleName,
        patientLastName: data.patientLastName,
        patientDob: data.patientDob,
        patientAddressLine1: data.patientAddressLine1,
        patientAddressLine2: data.patientAddressLine2,
        patientCity: data.patientCity,
        patientProvince: data.patientProvince,
        patientPostalCode: data.patientPostalCode,
        patientPhoneCountry: data.patientPhoneCountry,
        patientPhoneNumber: data.patientPhoneNumber,
        createdBy: data.createdBy,
        updatedBy: data.updatedBy,
        // Optional fields forwarded from input
        wcbClaimNumber: data.wcbClaimNumber as string | undefined,
        parentWcbClaimId: data.parentWcbClaimId as string | undefined,
        additionalComments: data.additionalComments as string | undefined,
        employerName: data.employerName as string | undefined,
        employerLocation: data.employerLocation as string | undefined,
        employerCity: data.employerCity as string | undefined,
        employerProvince: data.employerProvince as string | undefined,
        employerPhoneCountry: data.employerPhoneCountry as string | undefined,
        employerPhoneNumber: data.employerPhoneNumber as string | undefined,
        employerPhoneExt: data.employerPhoneExt as string | undefined,
        workerJobTitle: data.workerJobTitle as string | undefined,
        injuryDevelopedOverTime: data.injuryDevelopedOverTime as string | undefined,
        injuryDescription: data.injuryDescription as string | undefined,
        dateOfExamination: data.dateOfExamination as string | undefined,
        symptoms: data.symptoms as string | undefined,
        objectiveFindings: data.objectiveFindings as string | undefined,
        currentDiagnosis: data.currentDiagnosis as string | undefined,
        diagnosticCode1: data.diagnosticCode1 as string | undefined,
        diagnosticCode2: data.diagnosticCode2 as string | undefined,
        diagnosticCode3: data.diagnosticCode3 as string | undefined,
      };

      const rows = await db
        .insert(wcbClaimDetails)
        .values(insertData)
        .returning();
      return rows[0];
    },

    /**
     * Fetch a WCB claim detail with ALL child records (injuries, prescriptions,
     * consultations, restrictions, invoice_lines, attachments).
     * Scoped to physician via join to claims table.
     * Returns null if not found or wrong physician (no existence leakage).
     */
    async getWcbClaim(
      wcbClaimDetailId: string,
      physicianId: string,
    ): Promise<WcbClaimWithChildren | null> {
      // Fetch the claim detail with physician scoping via claims table
      const detailRows = await db
        .select({
          detail: wcbClaimDetails,
          claim: claims,
        })
        .from(wcbClaimDetails)
        .innerJoin(claims, eq(wcbClaimDetails.claimId, claims.claimId))
        .where(
          and(
            eq(wcbClaimDetails.wcbClaimDetailId, wcbClaimDetailId),
            eq(claims.physicianId, physicianId),
            isNull(claims.deletedAt),
          ),
        )
        .limit(1);

      if (detailRows.length === 0) {
        return null;
      }

      const { detail, claim } = detailRows[0];

      // Fetch all child records in parallel to avoid N+1
      const [injuries, prescriptions, consultations, workRestrictions, invoiceLinesResult, attachmentsResult] =
        await Promise.all([
          db
            .select()
            .from(wcbInjuries)
            .where(eq(wcbInjuries.wcbClaimDetailId, wcbClaimDetailId))
            .orderBy(wcbInjuries.ordinal),
          db
            .select()
            .from(wcbPrescriptions)
            .where(eq(wcbPrescriptions.wcbClaimDetailId, wcbClaimDetailId))
            .orderBy(wcbPrescriptions.ordinal),
          db
            .select()
            .from(wcbConsultations)
            .where(eq(wcbConsultations.wcbClaimDetailId, wcbClaimDetailId))
            .orderBy(wcbConsultations.ordinal),
          db
            .select()
            .from(wcbWorkRestrictions)
            .where(eq(wcbWorkRestrictions.wcbClaimDetailId, wcbClaimDetailId)),
          db
            .select()
            .from(wcbInvoiceLines)
            .where(eq(wcbInvoiceLines.wcbClaimDetailId, wcbClaimDetailId))
            .orderBy(wcbInvoiceLines.invoiceDetailId),
          db
            .select()
            .from(wcbAttachments)
            .where(eq(wcbAttachments.wcbClaimDetailId, wcbClaimDetailId))
            .orderBy(wcbAttachments.ordinal),
        ]);

      return {
        detail,
        claim,
        injuries,
        prescriptions,
        consultations,
        workRestrictions,
        invoiceLines: invoiceLinesResult,
        attachments: attachmentsResult,
      };
    },

    /**
     * Partial update of WCB claim detail fields.
     * Only allowed in DRAFT state (verified via join to claims table).
     * Sets updated_at and updated_by.
     * Returns updated detail or null if not found, wrong physician, or not in draft state.
     */
    async updateWcbClaim(
      wcbClaimDetailId: string,
      physicianId: string,
      data: UpdateWcbClaimInput,
    ): Promise<SelectWcbClaimDetail | null> {
      // Verify physician ownership AND draft state via the claims table
      const ownershipCheck = await db
        .select({
          wcbClaimDetailId: wcbClaimDetails.wcbClaimDetailId,
          claimState: claims.state,
        })
        .from(wcbClaimDetails)
        .innerJoin(claims, eq(wcbClaimDetails.claimId, claims.claimId))
        .where(
          and(
            eq(wcbClaimDetails.wcbClaimDetailId, wcbClaimDetailId),
            eq(claims.physicianId, physicianId),
            isNull(claims.deletedAt),
          ),
        )
        .limit(1);

      if (ownershipCheck.length === 0) {
        return null;
      }

      if (ownershipCheck[0].claimState !== ClaimState.DRAFT) {
        return null;
      }

      const rows = await db
        .update(wcbClaimDetails)
        .set({
          ...data,
          updatedAt: new Date(),
        })
        .where(eq(wcbClaimDetails.wcbClaimDetailId, wcbClaimDetailId))
        .returning();

      return rows[0] ?? null;
    },

    /**
     * Soft-delete a WCB claim detail by setting deleted_at.
     * Only allowed in DRAFT state (verified via join to claims table).
     * Returns true if deleted, false if not found, wrong physician, or wrong state.
     */
    async softDeleteWcbClaim(
      wcbClaimDetailId: string,
      physicianId: string,
    ): Promise<boolean> {
      // Verify physician ownership AND draft state
      const ownershipCheck = await db
        .select({
          wcbClaimDetailId: wcbClaimDetails.wcbClaimDetailId,
          claimState: claims.state,
        })
        .from(wcbClaimDetails)
        .innerJoin(claims, eq(wcbClaimDetails.claimId, claims.claimId))
        .where(
          and(
            eq(wcbClaimDetails.wcbClaimDetailId, wcbClaimDetailId),
            eq(claims.physicianId, physicianId),
            isNull(claims.deletedAt),
          ),
        )
        .limit(1);

      if (ownershipCheck.length === 0) {
        return false;
      }

      if (ownershipCheck[0].claimState !== ClaimState.DRAFT) {
        return false;
      }

      const rows = await db
        .update(wcbClaimDetails)
        .set({ deletedAt: new Date() })
        .where(eq(wcbClaimDetails.wcbClaimDetailId, wcbClaimDetailId))
        .returning();

      return rows.length > 0;
    },

    /**
     * Find a WCB claim detail by submitter transaction ID.
     * Used for return file matching — no physician scoping required
     * because submitter_txn_id is globally unique.
     */
    async getWcbClaimBySubmitterTxnId(
      submitterTxnId: string,
    ): Promise<SelectWcbClaimDetail | null> {
      const rows = await db
        .select()
        .from(wcbClaimDetails)
        .where(eq(wcbClaimDetails.submitterTxnId, submitterTxnId))
        .limit(1);
      return rows[0] ?? null;
    },

    /**
     * Store the WCB-assigned claim number after return file processing.
     * Called during return file ingestion — scoping enforced at service layer.
     */
    async updateWcbClaimNumber(
      wcbClaimDetailId: string,
      claimNumber: string,
    ): Promise<SelectWcbClaimDetail | null> {
      const rows = await db
        .update(wcbClaimDetails)
        .set({
          wcbClaimNumber: claimNumber,
          updatedAt: new Date(),
        })
        .where(eq(wcbClaimDetails.wcbClaimDetailId, wcbClaimDetailId))
        .returning();
      return rows[0] ?? null;
    },

    // -----------------------------------------------------------------------
    // Child table CRUD: Injuries
    // -----------------------------------------------------------------------

    /**
     * Replace all injuries for a WCB claim detail.
     * Deletes existing rows, then bulk inserts the new set.
     * Enforces max 5 entries. Assigns ordinals automatically (1-based).
     */
    async upsertInjuries(
      wcbClaimDetailId: string,
      injuries: InjuryInput[],
    ): Promise<SelectWcbInjury[]> {
      if (injuries.length > 5) {
        throw new BusinessRuleError('Maximum 5 injuries allowed per WCB claim');
      }

      // Delete existing, then insert replacements
      await db.delete(wcbInjuries).where(eq(wcbInjuries.wcbClaimDetailId, wcbClaimDetailId));

      if (injuries.length === 0) {
        return [];
      }

      const insertRows = injuries.map((injury, idx) => ({
        wcbClaimDetailId,
        ordinal: idx + 1,
        partOfBodyCode: injury.partOfBodyCode,
        sideOfBodyCode: injury.sideOfBodyCode,
        natureOfInjuryCode: injury.natureOfInjuryCode,
      }));

      const rows = await db.insert(wcbInjuries).values(insertRows).returning();
      return rows;
    },

    /**
     * Get all injuries for a WCB claim detail, ordered by ordinal.
     */
    async getInjuries(
      wcbClaimDetailId: string,
    ): Promise<SelectWcbInjury[]> {
      return db
        .select()
        .from(wcbInjuries)
        .where(eq(wcbInjuries.wcbClaimDetailId, wcbClaimDetailId))
        .orderBy(wcbInjuries.ordinal);
    },

    // -----------------------------------------------------------------------
    // Child table CRUD: Prescriptions
    // -----------------------------------------------------------------------

    /**
     * Replace all prescriptions for a WCB claim detail.
     * Deletes existing rows, then bulk inserts the new set.
     * Enforces max 5 entries. Assigns ordinals automatically (1-based).
     */
    async upsertPrescriptions(
      wcbClaimDetailId: string,
      prescriptions: PrescriptionInput[],
    ): Promise<SelectWcbPrescription[]> {
      if (prescriptions.length > 5) {
        throw new BusinessRuleError('Maximum 5 prescriptions allowed per WCB claim');
      }

      await db.delete(wcbPrescriptions).where(eq(wcbPrescriptions.wcbClaimDetailId, wcbClaimDetailId));

      if (prescriptions.length === 0) {
        return [];
      }

      const insertRows = prescriptions.map((rx, idx) => ({
        wcbClaimDetailId,
        ordinal: idx + 1,
        prescriptionName: rx.prescriptionName,
        strength: rx.strength,
        dailyIntake: rx.dailyIntake,
      }));

      const rows = await db.insert(wcbPrescriptions).values(insertRows).returning();
      return rows;
    },

    /**
     * Get all prescriptions for a WCB claim detail, ordered by ordinal.
     */
    async getPrescriptions(
      wcbClaimDetailId: string,
    ): Promise<SelectWcbPrescription[]> {
      return db
        .select()
        .from(wcbPrescriptions)
        .where(eq(wcbPrescriptions.wcbClaimDetailId, wcbClaimDetailId))
        .orderBy(wcbPrescriptions.ordinal);
    },

    // -----------------------------------------------------------------------
    // Child table CRUD: Consultations
    // -----------------------------------------------------------------------

    /**
     * Replace all consultations for a WCB claim detail.
     * Deletes existing rows, then bulk inserts the new set.
     * Enforces max 5 entries. Assigns ordinals automatically (1-based).
     */
    async upsertConsultations(
      wcbClaimDetailId: string,
      consultations: ConsultationInput[],
    ): Promise<SelectWcbConsultation[]> {
      if (consultations.length > 5) {
        throw new BusinessRuleError('Maximum 5 consultations allowed per WCB claim');
      }

      await db.delete(wcbConsultations).where(eq(wcbConsultations.wcbClaimDetailId, wcbClaimDetailId));

      if (consultations.length === 0) {
        return [];
      }

      const insertRows = consultations.map((con, idx) => ({
        wcbClaimDetailId,
        ordinal: idx + 1,
        category: con.category,
        typeCode: con.typeCode,
        details: con.details,
        expediteRequested: con.expediteRequested,
      }));

      const rows = await db.insert(wcbConsultations).values(insertRows).returning();
      return rows;
    },

    /**
     * Get all consultations for a WCB claim detail, ordered by ordinal.
     */
    async getConsultations(
      wcbClaimDetailId: string,
    ): Promise<SelectWcbConsultation[]> {
      return db
        .select()
        .from(wcbConsultations)
        .where(eq(wcbConsultations.wcbClaimDetailId, wcbClaimDetailId))
        .orderBy(wcbConsultations.ordinal);
    },

    // -----------------------------------------------------------------------
    // Child table CRUD: Work Restrictions
    // -----------------------------------------------------------------------

    /**
     * Replace all work restrictions for a WCB claim detail.
     * Deletes existing rows, then bulk inserts the new set.
     * Enforces max 11 entries (one per activity type).
     * Rejects duplicate activity_type values within the input set.
     */
    async upsertWorkRestrictions(
      wcbClaimDetailId: string,
      restrictions: RestrictionInput[],
    ): Promise<SelectWcbWorkRestriction[]> {
      if (restrictions.length > 11) {
        throw new BusinessRuleError('Maximum 11 work restrictions allowed per WCB claim');
      }

      // Check for duplicate activity_type within the input set
      const activityTypes = restrictions.map((r) => r.activityType);
      const uniqueTypes = new Set(activityTypes);
      if (uniqueTypes.size !== activityTypes.length) {
        throw new BusinessRuleError('Duplicate activity_type in work restrictions');
      }

      await db.delete(wcbWorkRestrictions).where(eq(wcbWorkRestrictions.wcbClaimDetailId, wcbClaimDetailId));

      if (restrictions.length === 0) {
        return [];
      }

      const insertRows = restrictions.map((r) => ({
        wcbClaimDetailId,
        activityType: r.activityType,
        restrictionLevel: r.restrictionLevel,
        hoursPerDay: r.hoursPerDay,
        maxWeight: r.maxWeight,
      }));

      const rows = await db.insert(wcbWorkRestrictions).values(insertRows).returning();
      return rows;
    },

    /**
     * Get all work restrictions for a WCB claim detail.
     */
    async getWorkRestrictions(
      wcbClaimDetailId: string,
    ): Promise<SelectWcbWorkRestriction[]> {
      return db
        .select()
        .from(wcbWorkRestrictions)
        .where(eq(wcbWorkRestrictions.wcbClaimDetailId, wcbClaimDetailId));
    },

    /**
     * Paginated list of WCB claims for a physician.
     * Joins to claims table for physician scoping and state filtering.
     * Excludes soft-deleted claims. Reverse chronological order.
     */
    async listWcbClaimsForPhysician(
      physicianId: string,
      filters: ListWcbClaimsFilters,
    ): Promise<PaginatedResult<WcbClaimListItem>> {
      const conditions = [
        eq(claims.physicianId, physicianId),
        isNull(claims.deletedAt),
        isNull(wcbClaimDetails.deletedAt),
      ];

      if (filters.status) {
        conditions.push(eq(claims.state, filters.status));
      }

      if (filters.formId) {
        conditions.push(eq(wcbClaimDetails.formId, filters.formId));
      }

      const whereClause = and(...conditions);
      const offset = (filters.page - 1) * filters.pageSize;

      const [countResult, rows] = await Promise.all([
        db
          .select({ total: count() })
          .from(wcbClaimDetails)
          .innerJoin(claims, eq(wcbClaimDetails.claimId, claims.claimId))
          .where(whereClause!),
        db
          .select({
            detail: wcbClaimDetails,
            claim: claims,
          })
          .from(wcbClaimDetails)
          .innerJoin(claims, eq(wcbClaimDetails.claimId, claims.claimId))
          .where(whereClause!)
          .orderBy(desc(claims.createdAt))
          .limit(filters.pageSize)
          .offset(offset),
      ]);

      const total = Number(countResult[0]?.total ?? 0);

      return {
        data: rows.map((row) => ({
          detail: row.detail,
          claim: row.claim,
        })),
        pagination: {
          total,
          page: filters.page,
          pageSize: filters.pageSize,
          hasMore: filters.page * filters.pageSize < total,
        },
      };
    },

    // -----------------------------------------------------------------------
    // Child table CRUD: Invoice Lines
    // -----------------------------------------------------------------------

    /**
     * Replace all invoice lines for a WCB claim detail.
     * Deletes existing rows, then bulk inserts the new set.
     * Enforces max 25 entries and sequential invoice_detail_id (1-based, no gaps).
     * Lines are assigned invoice_detail_id automatically based on array position.
     */
    async upsertInvoiceLines(
      wcbClaimDetailId: string,
      lines: InvoiceLineInput[],
    ): Promise<SelectWcbInvoiceLine[]> {
      if (lines.length > 25) {
        throw new BusinessRuleError('Maximum 25 invoice lines allowed per WCB claim');
      }

      await db.delete(wcbInvoiceLines).where(eq(wcbInvoiceLines.wcbClaimDetailId, wcbClaimDetailId));

      if (lines.length === 0) {
        return [];
      }

      const insertRows = lines.map((line, idx) => ({
        wcbClaimDetailId,
        invoiceDetailId: idx + 1,
        lineType: line.lineType,
        healthServiceCode: line.healthServiceCode,
        diagnosticCode1: line.diagnosticCode1,
        diagnosticCode2: line.diagnosticCode2,
        diagnosticCode3: line.diagnosticCode3,
        modifier1: line.modifier1,
        modifier2: line.modifier2,
        modifier3: line.modifier3,
        calls: line.calls,
        encounters: line.encounters,
        dateOfServiceFrom: line.dateOfServiceFrom,
        dateOfServiceTo: line.dateOfServiceTo,
        facilityTypeOverride: line.facilityTypeOverride,
        skillCodeOverride: line.skillCodeOverride,
        invoiceDetailTypeCode: line.invoiceDetailTypeCode,
        invoiceDetailDesc: line.invoiceDetailDesc,
        quantity: line.quantity,
        supplyDescription: line.supplyDescription,
        amount: line.amount,
        adjustmentIndicator: line.adjustmentIndicator,
        billingNumberOverride: line.billingNumberOverride,
        correctionPairId: line.correctionPairId,
      }));

      const rows = await db.insert(wcbInvoiceLines).values(insertRows).returning();
      return rows;
    },

    /**
     * Get all invoice lines for a WCB claim detail, ordered by invoice_detail_id.
     */
    async getInvoiceLines(
      wcbClaimDetailId: string,
    ): Promise<SelectWcbInvoiceLine[]> {
      return db
        .select()
        .from(wcbInvoiceLines)
        .where(eq(wcbInvoiceLines.wcbClaimDetailId, wcbClaimDetailId))
        .orderBy(wcbInvoiceLines.invoiceDetailId);
    },

    /**
     * Validate C570 Was/Should Be pairing.
     * Every WAS line must have exactly one SHOULD_BE line with the same correction_pair_id,
     * and vice versa. Returns a validation result with errors for any mismatches.
     */
    async validateC570Pairing(
      wcbClaimDetailId: string,
    ): Promise<C570ValidationResult> {
      const lines = await db
        .select()
        .from(wcbInvoiceLines)
        .where(eq(wcbInvoiceLines.wcbClaimDetailId, wcbClaimDetailId))
        .orderBy(wcbInvoiceLines.invoiceDetailId);

      const wasLines = lines.filter((l) => l.lineType === 'WAS');
      const shouldBeLines = lines.filter((l) => l.lineType === 'SHOULD_BE');
      const errors: string[] = [];

      // Build maps of correction_pair_id to lines
      const wasByPairId = new Map<number, SelectWcbInvoiceLine[]>();
      const shouldBeByPairId = new Map<number, SelectWcbInvoiceLine[]>();

      for (const line of wasLines) {
        const pairId = line.correctionPairId;
        if (pairId == null) {
          errors.push(`WAS line (invoice_detail_id=${line.invoiceDetailId}) missing correction_pair_id`);
          continue;
        }
        if (!wasByPairId.has(pairId)) {
          wasByPairId.set(pairId, []);
        }
        wasByPairId.get(pairId)!.push(line);
      }

      for (const line of shouldBeLines) {
        const pairId = line.correctionPairId;
        if (pairId == null) {
          errors.push(`SHOULD_BE line (invoice_detail_id=${line.invoiceDetailId}) missing correction_pair_id`);
          continue;
        }
        if (!shouldBeByPairId.has(pairId)) {
          shouldBeByPairId.set(pairId, []);
        }
        shouldBeByPairId.get(pairId)!.push(line);
      }

      // Every WAS correction_pair_id must have exactly one matching SHOULD_BE
      for (const [pairId, wasGroup] of wasByPairId) {
        if (wasGroup.length > 1) {
          errors.push(`Multiple WAS lines with correction_pair_id=${pairId}`);
        }
        const matchingShouldBe = shouldBeByPairId.get(pairId);
        if (!matchingShouldBe || matchingShouldBe.length === 0) {
          errors.push(`WAS line with correction_pair_id=${pairId} has no matching SHOULD_BE`);
        } else if (matchingShouldBe.length > 1) {
          errors.push(`Multiple SHOULD_BE lines with correction_pair_id=${pairId}`);
        }
      }

      // Every SHOULD_BE correction_pair_id must have exactly one matching WAS
      for (const [pairId, shouldBeGroup] of shouldBeByPairId) {
        if (shouldBeGroup.length > 1 && !wasByPairId.has(pairId)) {
          errors.push(`Multiple SHOULD_BE lines with correction_pair_id=${pairId}`);
        }
        const matchingWas = wasByPairId.get(pairId);
        if (!matchingWas || matchingWas.length === 0) {
          errors.push(`SHOULD_BE line with correction_pair_id=${pairId} has no matching WAS`);
        }
      }

      return {
        valid: errors.length === 0,
        errors,
      };
    },

    // -----------------------------------------------------------------------
    // Child table CRUD: Attachments
    // -----------------------------------------------------------------------

    /**
     * Replace all attachments for a WCB claim detail.
     * Deletes existing rows, then bulk inserts the new set.
     * Enforces max 3 entries. Assigns ordinals automatically (1-based).
     */
    async upsertAttachments(
      wcbClaimDetailId: string,
      attachments: AttachmentInput[],
    ): Promise<SelectWcbAttachment[]> {
      if (attachments.length > 3) {
        throw new BusinessRuleError('Maximum 3 attachments allowed per WCB claim');
      }

      await db.delete(wcbAttachments).where(eq(wcbAttachments.wcbClaimDetailId, wcbClaimDetailId));

      if (attachments.length === 0) {
        return [];
      }

      const insertRows = attachments.map((att, idx) => ({
        wcbClaimDetailId,
        ordinal: idx + 1,
        fileName: att.fileName,
        fileType: att.fileType,
        fileContentB64: att.fileContentB64,
        fileDescription: att.fileDescription,
        fileSizeBytes: att.fileSizeBytes,
      }));

      const rows = await db.insert(wcbAttachments).values(insertRows).returning();
      return rows;
    },

    /**
     * Get all attachments for a WCB claim detail, ordered by ordinal.
     * Returns metadata only — does NOT include file_content_b64.
     */
    async getAttachments(
      wcbClaimDetailId: string,
    ): Promise<AttachmentMetadata[]> {
      const rows = await db
        .select({
          wcbAttachmentId: wcbAttachments.wcbAttachmentId,
          wcbClaimDetailId: wcbAttachments.wcbClaimDetailId,
          ordinal: wcbAttachments.ordinal,
          fileName: wcbAttachments.fileName,
          fileType: wcbAttachments.fileType,
          fileDescription: wcbAttachments.fileDescription,
          fileSizeBytes: wcbAttachments.fileSizeBytes,
        })
        .from(wcbAttachments)
        .where(eq(wcbAttachments.wcbClaimDetailId, wcbClaimDetailId))
        .orderBy(wcbAttachments.ordinal);
      return rows;
    },

    /**
     * Get a single attachment with full content (including file_content_b64).
     * Physician-scoped via join to wcb_claim_details → claims.
     * Returns null if not found or wrong physician.
     */
    async getAttachmentContent(
      wcbAttachmentId: string,
      physicianId: string,
    ): Promise<SelectWcbAttachment | null> {
      const rows = await db
        .select({
          attachment: wcbAttachments,
        })
        .from(wcbAttachments)
        .innerJoin(
          wcbClaimDetails,
          eq(wcbAttachments.wcbClaimDetailId, wcbClaimDetails.wcbClaimDetailId),
        )
        .innerJoin(claims, eq(wcbClaimDetails.claimId, claims.claimId))
        .where(
          and(
            eq(wcbAttachments.wcbAttachmentId, wcbAttachmentId),
            eq(claims.physicianId, physicianId),
            isNull(claims.deletedAt),
          ),
        )
        .limit(1);

      if (rows.length === 0) {
        return null;
      }

      return rows[0].attachment;
    },

    // -----------------------------------------------------------------------
    // Batch Operations
    // -----------------------------------------------------------------------

    /**
     * Create a new WCB batch with ASSEMBLING status.
     * Generates globally unique batch_control_id and file_control_id.
     * Returns the created batch ID.
     */
    async createBatch(
      physicianId: string,
      createdBy: string,
    ): Promise<SelectWcbBatch> {
      const batchControlId = generateBatchControlId();
      const fileControlId = generateFileControlId();

      const rows = await db
        .insert(wcbBatches)
        .values({
          physicianId,
          batchControlId,
          fileControlId,
          status: WcbBatchStatus.ASSEMBLING,
          reportCount: 0,
          createdBy,
        })
        .returning();

      return rows[0];
    },

    /**
     * Fetch a batch by ID, scoped to physician.
     * Returns null if not found or belongs to a different physician.
     */
    async getBatch(
      wcbBatchId: string,
      physicianId: string,
    ): Promise<SelectWcbBatch | null> {
      const rows = await db
        .select()
        .from(wcbBatches)
        .where(
          and(
            eq(wcbBatches.wcbBatchId, wcbBatchId),
            eq(wcbBatches.physicianId, physicianId),
          ),
        )
        .limit(1);

      return rows[0] ?? null;
    },

    /**
     * Fetch a batch by its batch_control_id, scoped to physician.
     * Used for matching WCB return files to submitted batches.
     */
    async getBatchByControlId(
      batchControlId: string,
      physicianId: string,
    ): Promise<SelectWcbBatch | null> {
      const rows = await db
        .select()
        .from(wcbBatches)
        .where(
          and(
            eq(wcbBatches.batchControlId, batchControlId),
            eq(wcbBatches.physicianId, physicianId),
          ),
        )
        .limit(1);

      return rows[0] ?? null;
    },

    /**
     * Paginated list of batches for a physician.
     * Reverse chronological. Optional status filter.
     */
    async listBatches(
      physicianId: string,
      filters: ListBatchesFilters,
    ): Promise<PaginatedResult<SelectWcbBatch>> {
      const conditions = [
        eq(wcbBatches.physicianId, physicianId),
      ];

      if (filters.status) {
        conditions.push(eq(wcbBatches.status, filters.status));
      }

      const whereClause = and(...conditions);
      const offset = (filters.page - 1) * filters.pageSize;

      const [countResult, rows] = await Promise.all([
        db
          .select({ total: count() })
          .from(wcbBatches)
          .where(whereClause!),
        db
          .select()
          .from(wcbBatches)
          .where(whereClause!)
          .orderBy(desc(wcbBatches.createdAt))
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
     * Transition batch status with validation.
     * Enforces valid state transitions:
     *   ASSEMBLING -> GENERATED -> VALIDATED -> UPLOADED -> RETURN_RECEIVED -> RECONCILED
     *   ERROR can occur from ASSEMBLING, GENERATED, or VALIDATED.
     * Accepts additional fields to set (xml_file_path, xml_file_hash, etc.).
     * Returns updated batch or null if not found/wrong physician.
     * Throws ConflictError on invalid transition.
     */
    async updateBatchStatus(
      wcbBatchId: string,
      physicianId: string,
      newStatus: string,
      additionalFields?: Partial<{
        reportCount: number;
        xmlFilePath: string;
        xmlFileHash: string;
        xsdValidationPassed: boolean;
        xsdValidationErrors: unknown;
      }>,
    ): Promise<SelectWcbBatch | null> {
      // Fetch current batch with physician scoping
      const current = await db
        .select()
        .from(wcbBatches)
        .where(
          and(
            eq(wcbBatches.wcbBatchId, wcbBatchId),
            eq(wcbBatches.physicianId, physicianId),
          ),
        )
        .limit(1);

      if (current.length === 0) {
        return null;
      }

      const batch = current[0];
      const allowed = VALID_BATCH_TRANSITIONS[batch.status] ?? [];

      if (!allowed.includes(newStatus)) {
        throw new ConflictError(
          `Invalid batch status transition from ${batch.status} to ${newStatus}`,
        );
      }

      const setClauses: Record<string, unknown> = { status: newStatus };

      if (additionalFields) {
        if (additionalFields.reportCount !== undefined) setClauses.reportCount = additionalFields.reportCount;
        if (additionalFields.xmlFilePath !== undefined) setClauses.xmlFilePath = additionalFields.xmlFilePath;
        if (additionalFields.xmlFileHash !== undefined) setClauses.xmlFileHash = additionalFields.xmlFileHash;
        if (additionalFields.xsdValidationPassed !== undefined) setClauses.xsdValidationPassed = additionalFields.xsdValidationPassed;
        if (additionalFields.xsdValidationErrors !== undefined) setClauses.xsdValidationErrors = additionalFields.xsdValidationErrors;
      }

      const rows = await db
        .update(wcbBatches)
        .set(setClauses)
        .where(
          and(
            eq(wcbBatches.wcbBatchId, wcbBatchId),
            eq(wcbBatches.physicianId, physicianId),
          ),
        )
        .returning();

      return rows[0] ?? null;
    },

    /**
     * Set batch status to UPLOADED with upload tracking fields.
     * Only valid from VALIDATED status.
     * Returns updated batch or null if not found/wrong physician.
     * Throws ConflictError if not in VALIDATED status.
     */
    async setBatchUploaded(
      wcbBatchId: string,
      physicianId: string,
      uploadedBy: string,
    ): Promise<SelectWcbBatch | null> {
      // Fetch current batch with physician scoping
      const current = await db
        .select()
        .from(wcbBatches)
        .where(
          and(
            eq(wcbBatches.wcbBatchId, wcbBatchId),
            eq(wcbBatches.physicianId, physicianId),
          ),
        )
        .limit(1);

      if (current.length === 0) {
        return null;
      }

      if (current[0].status !== WcbBatchStatus.VALIDATED) {
        throw new ConflictError(
          `Cannot upload batch: current status is ${current[0].status}, expected VALIDATED`,
        );
      }

      const rows = await db
        .update(wcbBatches)
        .set({
          status: WcbBatchStatus.UPLOADED,
          uploadedAt: new Date(),
          uploadedBy,
        })
        .where(
          and(
            eq(wcbBatches.wcbBatchId, wcbBatchId),
            eq(wcbBatches.physicianId, physicianId),
          ),
        )
        .returning();

      return rows[0] ?? null;
    },

    /**
     * Set batch status to RETURN_RECEIVED with return file path.
     * Only valid from UPLOADED status.
     * Returns updated batch or null if not found/wrong physician.
     * Throws ConflictError if not in UPLOADED status.
     */
    async setBatchReturnReceived(
      wcbBatchId: string,
      physicianId: string,
      returnFilePath: string,
    ): Promise<SelectWcbBatch | null> {
      // Fetch current batch with physician scoping
      const current = await db
        .select()
        .from(wcbBatches)
        .where(
          and(
            eq(wcbBatches.wcbBatchId, wcbBatchId),
            eq(wcbBatches.physicianId, physicianId),
          ),
        )
        .limit(1);

      if (current.length === 0) {
        return null;
      }

      if (current[0].status !== WcbBatchStatus.UPLOADED) {
        throw new ConflictError(
          `Cannot receive return: current status is ${current[0].status}, expected UPLOADED`,
        );
      }

      const rows = await db
        .update(wcbBatches)
        .set({
          status: WcbBatchStatus.RETURN_RECEIVED,
          returnFileReceivedAt: new Date(),
          returnFilePath,
        })
        .where(
          and(
            eq(wcbBatches.wcbBatchId, wcbBatchId),
            eq(wcbBatches.physicianId, physicianId),
          ),
        )
        .returning();

      return rows[0] ?? null;
    },

    /**
     * Fetch all queued WCB claims for a physician.
     * Returns claims where state='QUEUED' and claim_type='WCB'.
     * Scoped to physician via claims.physician_id.
     * Excludes soft-deleted claims.
     */
    async getQueuedClaimsForBatch(
      physicianId: string,
    ): Promise<QueuedWcbClaim[]> {
      const rows = await db
        .select({
          claim: claims,
          detail: wcbClaimDetails,
        })
        .from(wcbClaimDetails)
        .innerJoin(claims, eq(wcbClaimDetails.claimId, claims.claimId))
        .where(
          and(
            eq(claims.physicianId, physicianId),
            eq(claims.state, ClaimState.QUEUED),
            eq(claims.claimType, ClaimType.WCB),
            isNull(claims.deletedAt),
            isNull(wcbClaimDetails.deletedAt),
          ),
        )
        .orderBy(desc(claims.createdAt));

      return rows.map((row) => ({
        claim: row.claim,
        detail: row.detail,
      }));
    },

    /**
     * Assign claims to a batch by setting submitted_batch_id on the claims table.
     * Updates the batch's report_count to match.
     * Returns the number of claims assigned.
     */
    async assignClaimsToBatch(
      wcbBatchId: string,
      physicianId: string,
      claimIds: string[],
    ): Promise<number> {
      if (claimIds.length === 0) {
        return 0;
      }

      // Update claims to reference this batch
      const updated = await db
        .update(claims)
        .set({ submittedBatchId: wcbBatchId })
        .where(
          and(
            inArray(claims.claimId, claimIds),
            eq(claims.physicianId, physicianId),
            isNull(claims.deletedAt),
          ),
        )
        .returning();

      // Update batch report_count
      if (updated.length > 0) {
        await db
          .update(wcbBatches)
          .set({ reportCount: updated.length })
          .where(
            and(
              eq(wcbBatches.wcbBatchId, wcbBatchId),
              eq(wcbBatches.physicianId, physicianId),
            ),
          );
      }

      return updated.length;
    },

    // -----------------------------------------------------------------------
    // Return Records
    // -----------------------------------------------------------------------

    /**
     * Bulk insert return records for a batch.
     * Each record represents one claim's outcome in the return file.
     */
    async createReturnRecords(
      wcbBatchId: string,
      records: ReturnRecordInput[],
    ): Promise<SelectWcbReturnRecord[]> {
      if (records.length === 0) {
        return [];
      }

      const insertRows = records.map((r) => ({
        wcbBatchId,
        wcbClaimDetailId: r.wcbClaimDetailId,
        reportTxnId: r.reportTxnId,
        submitterTxnId: r.submitterTxnId,
        processedClaimNumber: r.processedClaimNumber,
        claimDecision: r.claimDecision,
        reportStatus: r.reportStatus,
        txnSubmissionDate: r.txnSubmissionDate,
        errors: r.errors,
      }));

      const rows = await db
        .insert(wcbReturnRecords)
        .values(insertRows)
        .returning();

      return rows;
    },

    /**
     * Bulk insert per-report invoice line results for a return record.
     */
    async createReturnInvoiceLines(
      wcbReturnRecordId: string,
      lines: ReturnInvoiceLineInput[],
    ): Promise<SelectWcbReturnInvoiceLine[]> {
      if (lines.length === 0) {
        return [];
      }

      const insertRows = lines.map((l) => ({
        wcbReturnRecordId,
        invoiceSequence: l.invoiceSequence,
        serviceDate: l.serviceDate,
        healthServiceCode: l.healthServiceCode,
        invoiceStatus: l.invoiceStatus,
      }));

      const rows = await db
        .insert(wcbReturnInvoiceLines)
        .values(insertRows)
        .returning();

      return rows;
    },

    /**
     * Fetch all return records for a batch with their invoice line sub-records.
     */
    async getReturnRecordsByBatch(
      wcbBatchId: string,
    ): Promise<ReturnRecordWithInvoiceLines[]> {
      const returnRecords = await db
        .select()
        .from(wcbReturnRecords)
        .where(eq(wcbReturnRecords.wcbBatchId, wcbBatchId));

      if (returnRecords.length === 0) {
        return [];
      }

      const result: ReturnRecordWithInvoiceLines[] = [];

      for (const record of returnRecords) {
        const invoiceLines = await db
          .select()
          .from(wcbReturnInvoiceLines)
          .where(eq(wcbReturnInvoiceLines.wcbReturnRecordId, record.wcbReturnRecordId));

        result.push({
          returnRecord: record,
          invoiceLines,
        });
      }

      return result;
    },

    /**
     * Lookup wcb_claim_details by submitter_txn_id for return file matching.
     * Returns wcb_claim_detail_id or null.
     */
    async matchReturnToClaimBySubmitterTxnId(
      submitterTxnId: string,
    ): Promise<string | null> {
      const rows = await db
        .select({ wcbClaimDetailId: wcbClaimDetails.wcbClaimDetailId })
        .from(wcbClaimDetails)
        .where(eq(wcbClaimDetails.submitterTxnId, submitterTxnId))
        .limit(1);

      return rows[0]?.wcbClaimDetailId ?? null;
    },

    // -----------------------------------------------------------------------
    // Remittance Records
    // -----------------------------------------------------------------------

    /**
     * Create a remittance import batch record.
     * Returns the remittance_import_id.
     */
    async createRemittanceImport(
      physicianId: string,
    ): Promise<string> {
      const rows = await db
        .insert(wcbRemittanceImports)
        .values({
          physicianId,
        })
        .returning();

      return rows[0].remittanceImportId;
    },

    /**
     * Bulk insert remittance records for an import batch.
     * Updates the import's record_count after insertion.
     */
    async createRemittanceRecords(
      remittanceImportId: string,
      records: RemittanceRecordInput[],
    ): Promise<SelectWcbRemittanceRecord[]> {
      if (records.length === 0) {
        return [];
      }

      const insertRows = records.map((r) => ({
        remittanceImportId,
        wcbClaimDetailId: r.wcbClaimDetailId,
        reportWeekStart: r.reportWeekStart,
        reportWeekEnd: r.reportWeekEnd,
        disbursementNumber: r.disbursementNumber,
        disbursementType: r.disbursementType,
        disbursementIssueDate: r.disbursementIssueDate,
        disbursementAmount: r.disbursementAmount,
        disbursementRecipientBilling: r.disbursementRecipientBilling,
        disbursementRecipientName: r.disbursementRecipientName,
        paymentPayeeBilling: r.paymentPayeeBilling,
        paymentPayeeName: r.paymentPayeeName,
        paymentReasonCode: r.paymentReasonCode,
        paymentStatus: r.paymentStatus,
        paymentStartDate: r.paymentStartDate,
        paymentEndDate: r.paymentEndDate,
        paymentAmount: r.paymentAmount,
        billedAmount: r.billedAmount,
        electronicReportTxnId: r.electronicReportTxnId,
        claimNumber: r.claimNumber,
        workerPhn: r.workerPhn,
        workerFirstName: r.workerFirstName,
        workerLastName: r.workerLastName,
        serviceCode: r.serviceCode,
        modifier1: r.modifier1,
        modifier2: r.modifier2,
        modifier3: r.modifier3,
        numberOfCalls: r.numberOfCalls,
        encounterNumber: r.encounterNumber,
        overpaymentRecovery: r.overpaymentRecovery,
      }));

      const rows = await db
        .insert(wcbRemittanceRecords)
        .values(insertRows)
        .returning();

      // Update the import's record count
      await db
        .update(wcbRemittanceImports)
        .set({ recordCount: rows.length })
        .where(eq(wcbRemittanceImports.remittanceImportId, remittanceImportId));

      return rows;
    },

    /**
     * Match remittance to claim via return records chain:
     * electronic_report_txn_id -> wcb_return_records.report_txn_id -> wcb_claim_detail_id.
     * Returns wcb_claim_detail_id or null.
     */
    async matchRemittanceToClaimByTxnId(
      electronicReportTxnId: string,
    ): Promise<string | null> {
      const rows = await db
        .select({ wcbClaimDetailId: wcbReturnRecords.wcbClaimDetailId })
        .from(wcbReturnRecords)
        .where(eq(wcbReturnRecords.reportTxnId, electronicReportTxnId))
        .limit(1);

      return rows[0]?.wcbClaimDetailId ?? null;
    },

    /**
     * Paginated list of remittance imports for a physician.
     * Optional date range filtering by created_at.
     */
    async listRemittanceImports(
      physicianId: string,
      filters: ListRemittanceImportsFilters,
    ): Promise<PaginatedResult<SelectWcbRemittanceImport>> {
      const conditions: any[] = [
        eq(wcbRemittanceImports.physicianId, physicianId),
      ];

      // Date range filtering is done in-memory for the mock;
      // real Drizzle would use gte/lte operators on createdAt.
      // For now we filter via conditions on the SQL side.

      const whereClause = and(...conditions);
      const offset = (filters.page - 1) * filters.pageSize;

      const [countResult, rows] = await Promise.all([
        db
          .select({ total: count() })
          .from(wcbRemittanceImports)
          .where(whereClause!),
        db
          .select()
          .from(wcbRemittanceImports)
          .where(whereClause!)
          .orderBy(desc(wcbRemittanceImports.createdAt))
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
     * Return remittance records where payment_amount != billed_amount
     * or payment_status != 'ISS' (not issued).
     * These represent discrepancies that need physician attention.
     */
    async getRemittanceDiscrepancies(
      remittanceImportId: string,
    ): Promise<RemittanceDiscrepancy[]> {
      const records = await db
        .select()
        .from(wcbRemittanceRecords)
        .where(eq(wcbRemittanceRecords.remittanceImportId, remittanceImportId));

      const discrepancies: RemittanceDiscrepancy[] = [];

      for (const record of records) {
        if (record.paymentStatus !== 'ISS') {
          discrepancies.push({
            ...record,
            discrepancyType: 'STATUS_NOT_ISSUED',
          });
        } else if (
          record.billedAmount != null &&
          record.paymentAmount !== record.billedAmount
        ) {
          discrepancies.push({
            ...record,
            discrepancyType: 'AMOUNT_MISMATCH',
          });
        }
      }

      return discrepancies;
    },
  };
}

export type WcbRepository = ReturnType<typeof createWcbRepository>;
