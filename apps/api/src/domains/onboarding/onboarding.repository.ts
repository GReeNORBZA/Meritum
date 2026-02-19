import { eq, and, desc } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  onboardingProgress,
  imaRecords,
  type SelectOnboardingProgress,
  type SelectImaRecord,
} from '@meritum/shared/schemas/db/onboarding.schema.js';
import { REQUIRED_ONBOARDING_STEPS } from '@meritum/shared/constants/onboarding.constants.js';
import { ConflictError, BusinessRuleError } from '../../lib/errors.js';

// ---------------------------------------------------------------------------
// Step column mapping
// ---------------------------------------------------------------------------

const stepColumns = {
  1: 'step1Completed',
  2: 'step2Completed',
  3: 'step3Completed',
  4: 'step4Completed',
  5: 'step5Completed',
  6: 'step6Completed',
  7: 'step7Completed',
} as const;

type StepNumber = keyof typeof stepColumns;

// ---------------------------------------------------------------------------
// Onboarding Repository
// ---------------------------------------------------------------------------

export function createOnboardingRepository(db: NodePgDatabase) {
  return {
    /**
     * Insert a new onboarding progress record with all steps false.
     * Enforces unique provider_id — throws ConflictError on duplicate.
     */
    async createProgress(providerId: string): Promise<SelectOnboardingProgress> {
      try {
        const rows = await db
          .insert(onboardingProgress)
          .values({ providerId })
          .returning();
        return rows[0];
      } catch (err: any) {
        if (err.code === '23505') {
          throw new ConflictError('Onboarding progress already exists for this provider');
        }
        throw err;
      }
    },

    /**
     * Find onboarding progress by provider ID. Returns null if not found.
     */
    async findProgressByProviderId(
      providerId: string,
    ): Promise<SelectOnboardingProgress | null> {
      const rows = await db
        .select()
        .from(onboardingProgress)
        .where(eq(onboardingProgress.providerId, providerId))
        .limit(1);
      return rows[0] ?? null;
    },

    /**
     * Mark a specific onboarding step as completed.
     * Uses dynamic column name based on step number (1-7).
     * Returns updated progress record.
     */
    async markStepCompleted(
      providerId: string,
      stepNumber: number,
    ): Promise<SelectOnboardingProgress> {
      const colName = stepColumns[stepNumber as StepNumber];
      if (!colName) {
        throw new BusinessRuleError(`Invalid step number: ${stepNumber}`);
      }

      const rows = await db
        .update(onboardingProgress)
        .set({ [colName]: true })
        .where(eq(onboardingProgress.providerId, providerId))
        .returning();
      return rows[0];
    },

    /**
     * Mark onboarding as completed by setting completed_at.
     * Only succeeds when all required steps (1, 2, 3, 4, 7) are true.
     * Throws BusinessRuleError if required steps are incomplete.
     */
    async markOnboardingCompleted(
      providerId: string,
    ): Promise<SelectOnboardingProgress> {
      // Fetch current progress to verify required steps
      const rows = await db
        .select()
        .from(onboardingProgress)
        .where(eq(onboardingProgress.providerId, providerId))
        .limit(1);

      const progress = rows[0];
      if (!progress) {
        throw new BusinessRuleError('No onboarding progress found for this provider');
      }

      // Check all required steps are completed
      const incompleteSteps: number[] = [];
      for (const step of REQUIRED_ONBOARDING_STEPS) {
        const colName = stepColumns[step as StepNumber];
        if (colName && !progress[colName]) {
          incompleteSteps.push(step);
        }
      }

      if (incompleteSteps.length > 0) {
        throw new BusinessRuleError(
          'Cannot complete onboarding: required steps incomplete',
          { incompleteSteps },
        );
      }

      const updated = await db
        .update(onboardingProgress)
        .set({ completedAt: new Date() })
        .where(eq(onboardingProgress.providerId, providerId))
        .returning();
      return updated[0];
    },

    /**
     * Mark patient import as completed.
     */
    async markPatientImportCompleted(
      providerId: string,
    ): Promise<SelectOnboardingProgress> {
      const rows = await db
        .update(onboardingProgress)
        .set({ patientImportCompleted: true })
        .where(eq(onboardingProgress.providerId, providerId))
        .returning();
      return rows[0];
    },

    /**
     * Mark guided tour as completed.
     */
    async markGuidedTourCompleted(
      providerId: string,
    ): Promise<SelectOnboardingProgress> {
      const rows = await db
        .update(onboardingProgress)
        .set({ guidedTourCompleted: true })
        .where(eq(onboardingProgress.providerId, providerId))
        .returning();
      return rows[0];
    },

    /**
     * Mark guided tour as dismissed.
     */
    async markGuidedTourDismissed(
      providerId: string,
    ): Promise<SelectOnboardingProgress> {
      const rows = await db
        .update(onboardingProgress)
        .set({ guidedTourDismissed: true })
        .where(eq(onboardingProgress.providerId, providerId))
        .returning();
      return rows[0];
    },

    // -----------------------------------------------------------------------
    // IMA Records (Append-Only)
    // -----------------------------------------------------------------------

    /**
     * Insert an IMA acknowledgement record. Append-only — no update or delete
     * operations are exposed for IMA records.
     */
    async createImaRecord(data: {
      providerId: string;
      templateVersion: string;
      documentHash: string;
      ipAddress: string;
      userAgent: string;
    }): Promise<SelectImaRecord> {
      const rows = await db
        .insert(imaRecords)
        .values({
          providerId: data.providerId,
          templateVersion: data.templateVersion,
          documentHash: data.documentHash,
          ipAddress: data.ipAddress,
          userAgent: data.userAgent,
          acknowledgedAt: new Date(),
        })
        .returning();
      return rows[0];
    },

    /**
     * Return the most recent IMA record for a provider.
     * Used to check if current template version is acknowledged.
     */
    async findLatestImaRecord(
      providerId: string,
    ): Promise<SelectImaRecord | null> {
      const rows = await db
        .select()
        .from(imaRecords)
        .where(eq(imaRecords.providerId, providerId))
        .orderBy(desc(imaRecords.acknowledgedAt))
        .limit(1);
      return rows[0] ?? null;
    },

    /**
     * Return all IMA records for a provider in reverse chronological order.
     */
    async listImaRecords(providerId: string): Promise<SelectImaRecord[]> {
      return db
        .select()
        .from(imaRecords)
        .where(eq(imaRecords.providerId, providerId))
        .orderBy(desc(imaRecords.acknowledgedAt));
    },
  };
}

export type OnboardingRepository = ReturnType<typeof createOnboardingRepository>;
