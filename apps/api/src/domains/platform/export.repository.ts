// ============================================================================
// IMA-050: Complete Health Information Export Repository
// ============================================================================

import { eq } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';

// --- Patient tables ---
import { patients } from '@meritum/shared/schemas/db/patient.schema.js';

// --- Claim tables ---
import { claims, claimAuditHistory, shifts, claimExports } from '@meritum/shared/schemas/db/claim.schema.js';

// --- AHCIP tables ---
import { ahcipClaimDetails, ahcipBatches } from '@meritum/shared/schemas/db/ahcip.schema.js';

// --- WCB tables ---
import {
  wcbClaimDetails,
  wcbBatches,
  wcbRemittanceImports,
} from '@meritum/shared/schemas/db/wcb.schema.js';

// --- Provider tables ---
import {
  providers,
  businessArrangements,
  pcpcmEnrolments,
  practiceLocations,
  wcbConfigurations,
  delegateRelationships,
  submissionPreferences,
  hlinkConfigurations,
} from '@meritum/shared/schemas/db/provider.schema.js';
import { pcpcmPayments, pcpcmPanelEstimates } from '@meritum/shared/schemas/db/provider.schema.js';

// --- Analytics tables ---
import { analyticsCache, generatedReports, reportSubscriptions } from '@meritum/shared/schemas/db/analytics.schema.js';

// --- Intelligence tables ---
import { aiProviderLearning, aiSuggestionEvents } from '@meritum/shared/schemas/db/intelligence.schema.js';

// --- Mobile tables ---
import { edShifts, favouriteCodes } from '@meritum/shared/schemas/db/mobile.schema.js';

// --- Platform tables ---
import {
  subscriptions,
  imaAmendmentResponses,
  dataDestructionTracking,
} from '@meritum/shared/schemas/db/platform.schema.js';

// --- IAM tables ---
import { auditLog } from '@meritum/shared/schemas/db/iam.schema.js';

// ---------------------------------------------------------------------------
// Return type
// ---------------------------------------------------------------------------

export interface CompleteHealthInformation {
  // Patient data (including inactive)
  patients: unknown[];

  // Claim lifecycle
  claims: unknown[];
  claimAuditHistory: unknown[];
  shifts: unknown[];
  claimExports: unknown[];

  // AHCIP pathway
  ahcipClaimDetails: unknown[];
  ahcipBatches: unknown[];

  // WCB pathway
  wcbClaimDetails: unknown[];
  wcbBatches: unknown[];
  wcbRemittanceImports: unknown[];

  // Provider profile
  provider: unknown | null;
  businessArrangements: unknown[];
  practiceLocations: unknown[];
  wcbConfigurations: unknown[];
  delegateRelationships: unknown[];
  submissionPreferences: unknown[];
  hlinkConfigurations: unknown[];

  // PCPCM
  pcpcmEnrolments: unknown[];
  pcpcmPayments: unknown[];
  pcpcmPanelEstimates: unknown[];

  // Analytics
  analyticsCache: unknown[];
  generatedReports: unknown[];
  reportSubscriptions: unknown[];

  // Intelligence / AI
  aiProviderLearning: unknown[];
  aiSuggestionEvents: unknown[];

  // Mobile
  edShifts: unknown[];
  favouriteCodes: unknown[];

  // Platform
  subscription: unknown | null;
  imaAmendmentResponses: unknown[];

  // Audit log (scoped by userId = providerId)
  auditLog: unknown[];
}

// ---------------------------------------------------------------------------
// Repository factory
// ---------------------------------------------------------------------------

export function createExportRepository(db: NodePgDatabase) {
  return {
    /**
     * Retrieve ALL Health Information for a physician across every PHI table.
     * Every query is scoped by providerId. This is a complete dump of a
     * physician's data for HIA data portability compliance.
     *
     * SECURITY: This function should ONLY be callable by the authenticated
     * physician themselves (or admin for data hold scenarios). Enforce at
     * the handler/service layer.
     */
    async getCompleteHealthInformation(
      providerId: string,
    ): Promise<CompleteHealthInformation> {
      // --- Patients (ALL, including inactive/soft-deleted) ---
      const patientRows = await db
        .select()
        .from(patients)
        .where(eq(patients.providerId, providerId));

      // --- Claims (ALL states) ---
      const claimRows = await db
        .select()
        .from(claims)
        .where(eq(claims.physicianId, providerId));

      const claimIds = claimRows.map((c) => (c as any).claimId);

      // --- Claim audit history (scoped via claim_id FK → claims.physician_id) ---
      // We must join through claims to scope by provider
      let claimAuditRows: unknown[] = [];
      if (claimIds.length > 0) {
        claimAuditRows = await db
          .select({
            auditId: claimAuditHistory.auditId,
            claimId: claimAuditHistory.claimId,
            fieldName: claimAuditHistory.fieldName,
            oldValue: claimAuditHistory.oldValue,
            newValue: claimAuditHistory.newValue,
            changedBy: claimAuditHistory.changedBy,
            changedAt: claimAuditHistory.changedAt,
          })
          .from(claimAuditHistory)
          .innerJoin(claims, eq(claimAuditHistory.claimId, claims.claimId))
          .where(eq(claims.physicianId, providerId));
      }

      // --- Shifts ---
      const shiftRows = await db
        .select()
        .from(shifts)
        .where(eq(shifts.physicianId, providerId));

      // --- Claim exports ---
      const claimExportRows = await db
        .select()
        .from(claimExports)
        .where(eq(claimExports.physicianId, providerId));

      // --- AHCIP claim details (scoped via join to claims) ---
      let ahcipDetailRows: unknown[] = [];
      if (claimIds.length > 0) {
        ahcipDetailRows = await db
          .select()
          .from(ahcipClaimDetails)
          .innerJoin(claims, eq(ahcipClaimDetails.claimId, claims.claimId))
          .where(eq(claims.physicianId, providerId));
      }

      // --- AHCIP batches ---
      const ahcipBatchRows = await db
        .select()
        .from(ahcipBatches)
        .where(eq(ahcipBatches.physicianId, providerId));

      // --- WCB claim details (scoped via join to claims) ---
      let wcbDetailRows: unknown[] = [];
      if (claimIds.length > 0) {
        wcbDetailRows = await db
          .select()
          .from(wcbClaimDetails)
          .innerJoin(claims, eq(wcbClaimDetails.claimId, claims.claimId))
          .where(eq(claims.physicianId, providerId));
      }

      // --- WCB batches ---
      const wcbBatchRows = await db
        .select()
        .from(wcbBatches)
        .where(eq(wcbBatches.physicianId, providerId));

      // --- WCB remittance imports ---
      const wcbRemittanceRows = await db
        .select()
        .from(wcbRemittanceImports)
        .where(eq(wcbRemittanceImports.physicianId, providerId));

      // --- Provider profile ---
      const providerRows = await db
        .select()
        .from(providers)
        .where(eq(providers.providerId, providerId))
        .limit(1);

      // --- Business arrangements ---
      const baRows = await db
        .select()
        .from(businessArrangements)
        .where(eq(businessArrangements.providerId, providerId));

      // --- Practice locations ---
      const locationRows = await db
        .select()
        .from(practiceLocations)
        .where(eq(practiceLocations.providerId, providerId));

      // --- WCB configurations ---
      const wcbConfigRows = await db
        .select()
        .from(wcbConfigurations)
        .where(eq(wcbConfigurations.providerId, providerId));

      // --- Delegate relationships ---
      const delegateRows = await db
        .select()
        .from(delegateRelationships)
        .where(eq(delegateRelationships.physicianId, providerId));

      // --- Submission preferences ---
      const submPrefRows = await db
        .select()
        .from(submissionPreferences)
        .where(eq(submissionPreferences.providerId, providerId));

      // --- H-Link configurations ---
      const hlinkRows = await db
        .select()
        .from(hlinkConfigurations)
        .where(eq(hlinkConfigurations.providerId, providerId));

      // --- PCPCM enrolments ---
      const pcpcmEnrolmentRows = await db
        .select()
        .from(pcpcmEnrolments)
        .where(eq(pcpcmEnrolments.providerId, providerId));

      // --- PCPCM payments ---
      const pcpcmPaymentRows = await db
        .select()
        .from(pcpcmPayments)
        .where(eq(pcpcmPayments.providerId, providerId));

      // --- PCPCM panel estimates ---
      const pcpcmPanelRows = await db
        .select()
        .from(pcpcmPanelEstimates)
        .where(eq(pcpcmPanelEstimates.providerId, providerId));

      // --- Analytics cache ---
      const analyticsCacheRows = await db
        .select()
        .from(analyticsCache)
        .where(eq(analyticsCache.providerId, providerId));

      // --- Generated reports ---
      const reportRows = await db
        .select()
        .from(generatedReports)
        .where(eq(generatedReports.providerId, providerId));

      // --- Report subscriptions ---
      const reportSubRows = await db
        .select()
        .from(reportSubscriptions)
        .where(eq(reportSubscriptions.providerId, providerId));

      // --- AI provider learning ---
      const aiLearningRows = await db
        .select()
        .from(aiProviderLearning)
        .where(eq(aiProviderLearning.providerId, providerId));

      // --- AI suggestion events ---
      const aiSuggestionRows = await db
        .select()
        .from(aiSuggestionEvents)
        .where(eq(aiSuggestionEvents.providerId, providerId));

      // --- ED shifts ---
      const edShiftRows = await db
        .select()
        .from(edShifts)
        .where(eq(edShifts.providerId, providerId));

      // --- Favourite codes ---
      const favouriteCodeRows = await db
        .select()
        .from(favouriteCodes)
        .where(eq(favouriteCodes.providerId, providerId));

      // --- Subscription ---
      const subscriptionRows = await db
        .select()
        .from(subscriptions)
        .where(eq(subscriptions.providerId, providerId))
        .limit(1);

      // --- IMA amendment responses ---
      const imaResponseRows = await db
        .select()
        .from(imaAmendmentResponses)
        .where(eq(imaAmendmentResponses.providerId, providerId));

      // --- Audit log (userId = providerId in this system) ---
      const auditLogRows = await db
        .select()
        .from(auditLog)
        .where(eq(auditLog.userId, providerId));

      return {
        patients: patientRows,
        claims: claimRows,
        claimAuditHistory: claimAuditRows,
        shifts: shiftRows,
        claimExports: claimExportRows,
        ahcipClaimDetails: ahcipDetailRows,
        ahcipBatches: ahcipBatchRows,
        wcbClaimDetails: wcbDetailRows,
        wcbBatches: wcbBatchRows,
        wcbRemittanceImports: wcbRemittanceRows,
        provider: providerRows[0] ?? null,
        businessArrangements: baRows,
        practiceLocations: locationRows,
        wcbConfigurations: wcbConfigRows,
        delegateRelationships: delegateRows,
        submissionPreferences: submPrefRows,
        hlinkConfigurations: hlinkRows,
        pcpcmEnrolments: pcpcmEnrolmentRows,
        pcpcmPayments: pcpcmPaymentRows,
        pcpcmPanelEstimates: pcpcmPanelRows,
        analyticsCache: analyticsCacheRows,
        generatedReports: reportRows,
        reportSubscriptions: reportSubRows,
        aiProviderLearning: aiLearningRows,
        aiSuggestionEvents: aiSuggestionRows,
        edShifts: edShiftRows,
        favouriteCodes: favouriteCodeRows,
        subscription: subscriptionRows[0] ?? null,
        imaAmendmentResponses: imaResponseRows,
        auditLog: auditLogRows,
      };
    },
  };
}

export type ExportRepository = ReturnType<typeof createExportRepository>;
