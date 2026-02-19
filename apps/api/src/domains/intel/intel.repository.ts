import { eq, and, sql, count, desc, asc, or, isNull, inArray, gte, lte } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  aiRules,
  aiProviderLearning,
  aiSpecialtyCohorts,
  aiSuggestionEvents,
  type InsertAiRule,
  type SelectAiRule,
  type SelectAiProviderLearning,
  type InsertAiSpecialtyCohort,
  type SelectAiSpecialtyCohort,
  type InsertAiSuggestionEvent,
  type SelectAiSuggestionEvent,
} from '@meritum/shared/schemas/db/intelligence.schema.js';
import { providers } from '@meritum/shared/schemas/db/provider.schema.js';
import { SUPPRESSION_THRESHOLD, MIN_COHORT_SIZE } from '@meritum/shared/constants/intelligence.constants.js';

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
// Rule stats return type
// ---------------------------------------------------------------------------

export interface RuleStats {
  ruleId: string;
  totalShown: number;
  totalAccepted: number;
  totalDismissed: number;
  acceptanceRate: number;
  suppressionCount: number;
}

// ---------------------------------------------------------------------------
// Filter types
// ---------------------------------------------------------------------------

export interface RuleListFilters {
  category?: string;
  claimType?: string;
  isActive?: boolean;
  specialtyCode?: string;
  page: number;
  pageSize: number;
}

// ---------------------------------------------------------------------------
// Cohort types
// ---------------------------------------------------------------------------

export interface CohortAggregateInput {
  physicianCount: number;
  acceptanceRate: string;
  medianRevenueImpact?: string | null;
}

export interface CohortListFilters {
  specialtyCode?: string;
  ruleId?: string;
}

// ---------------------------------------------------------------------------
// Suggestion event filter types
// ---------------------------------------------------------------------------

export interface SuggestionEventInput {
  claimId: string;
  suggestionId: string;
  ruleId?: string | null;
  providerId: string;
  eventType: string;
  tier: number;
  category: string;
  revenueImpact?: string | null;
  dismissedReason?: string | null;
}

export interface ProviderEventFilters {
  category?: string;
  tier?: number;
  eventType?: string;
  startDate?: string;
  endDate?: string;
  page: number;
  pageSize: number;
}

export interface RulePerformanceFilters {
  eventType?: string;
  startDate?: string;
  endDate?: string;
}

// ---------------------------------------------------------------------------
// Learning summary return type
// ---------------------------------------------------------------------------

export interface LearningStateSummary {
  suppressedCount: number;
  topAcceptedCategories: { category: string; acceptedCount: number }[];
  totalSuggestionsShown: number;
  overallAcceptanceRate: number;
}

// ---------------------------------------------------------------------------
// Intel Repository — ai_rules CRUD
// ---------------------------------------------------------------------------

export function createIntelRepository(db: NodePgDatabase) {
  return {
    /**
     * Paginated list of rules with optional filters.
     * When specialtyCode is provided, include rules where specialty_filter
     * IS NULL (applies to all) or contains the given code.
     */
    async listRules(filters: RuleListFilters): Promise<PaginatedResult<SelectAiRule>> {
      const conditions: any[] = [];

      if (filters.category !== undefined) {
        conditions.push(eq(aiRules.category, filters.category));
      }

      if (filters.claimType !== undefined) {
        conditions.push(eq(aiRules.claimType, filters.claimType));
      }

      if (filters.isActive !== undefined) {
        conditions.push(eq(aiRules.isActive, filters.isActive));
      }

      if (filters.specialtyCode !== undefined) {
        conditions.push(
          or(
            isNull(aiRules.specialtyFilter),
            sql`${aiRules.specialtyFilter} @> ${JSON.stringify([filters.specialtyCode])}::jsonb`,
          ),
        );
      }

      const whereClause = conditions.length > 0 ? and(...conditions) : undefined;
      const offset = (filters.page - 1) * filters.pageSize;

      const [countResult, rows] = await Promise.all([
        db
          .select({ total: count() })
          .from(aiRules)
          .where(whereClause!),
        db
          .select()
          .from(aiRules)
          .where(whereClause!)
          .orderBy(desc(aiRules.createdAt))
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
     * Get a single rule by ID.
     */
    async getRule(ruleId: string): Promise<SelectAiRule | undefined> {
      const rows = await db
        .select()
        .from(aiRules)
        .where(eq(aiRules.ruleId, ruleId))
        .limit(1);
      return rows[0];
    },

    /**
     * Insert a new rule. Admin only (enforced at route level).
     */
    async createRule(data: InsertAiRule): Promise<SelectAiRule> {
      const rows = await db
        .insert(aiRules)
        .values(data)
        .returning();
      return rows[0];
    },

    /**
     * Partial update of a rule. Sets updated_at.
     */
    async updateRule(
      ruleId: string,
      data: Partial<InsertAiRule>,
    ): Promise<SelectAiRule | undefined> {
      const rows = await db
        .update(aiRules)
        .set({ ...data, updatedAt: new Date() })
        .where(eq(aiRules.ruleId, ruleId))
        .returning();
      return rows[0];
    },

    /**
     * Toggle is_active on a rule.
     */
    async activateRule(
      ruleId: string,
      isActive: boolean,
    ): Promise<SelectAiRule | undefined> {
      const rows = await db
        .update(aiRules)
        .set({ isActive, updatedAt: new Date() })
        .where(eq(aiRules.ruleId, ruleId))
        .returning();
      return rows[0];
    },

    /**
     * Fetch all active rules matching a claim type and specialty.
     * Returns rules where:
     * - is_active = true
     * - claim_type matches the given type OR is 'BOTH'
     * - specialty_filter IS NULL (applies to all) or contains the specialty code
     *
     * Optimised for Tier 1 evaluation hot path.
     */
    async getActiveRulesForClaim(
      claimType: string,
      specialtyCode: string,
    ): Promise<SelectAiRule[]> {
      const rows = await db
        .select()
        .from(aiRules)
        .where(
          and(
            eq(aiRules.isActive, true),
            or(
              eq(aiRules.claimType, claimType),
              eq(aiRules.claimType, 'BOTH'),
            ),
            or(
              isNull(aiRules.specialtyFilter),
              sql`${aiRules.specialtyFilter} @> ${JSON.stringify([specialtyCode])}::jsonb`,
            ),
          ),
        );
      return rows;
    },

    /**
     * Aggregate stats for a rule: total_shown, total_accepted, total_dismissed,
     * acceptance_rate, suppression_count across all physicians.
     * Joins ai_provider_learning.
     */
    async getRuleStats(ruleId: string): Promise<RuleStats> {
      const rows = await db
        .select({
          totalShown: sql<number>`COALESCE(SUM(${aiProviderLearning.timesShown}), 0)::int`,
          totalAccepted: sql<number>`COALESCE(SUM(${aiProviderLearning.timesAccepted}), 0)::int`,
          totalDismissed: sql<number>`COALESCE(SUM(${aiProviderLearning.timesDismissed}), 0)::int`,
          suppressionCount: sql<number>`COALESCE(SUM(CASE WHEN ${aiProviderLearning.isSuppressed} THEN 1 ELSE 0 END), 0)::int`,
        })
        .from(aiProviderLearning)
        .where(eq(aiProviderLearning.ruleId, ruleId));

      const row = rows[0];
      const totalShown = Number(row?.totalShown ?? 0);
      const totalAccepted = Number(row?.totalAccepted ?? 0);
      const totalDismissed = Number(row?.totalDismissed ?? 0);
      const suppressionCount = Number(row?.suppressionCount ?? 0);

      return {
        ruleId,
        totalShown,
        totalAccepted,
        totalDismissed,
        acceptanceRate: totalShown > 0 ? totalAccepted / totalShown : 0,
        suppressionCount,
      };
    },

    /**
     * Fetch rules derived from a specific SOMB version.
     * Used for change analysis when SOMB is updated.
     */
    async getRulesByVersion(sombVersion: string): Promise<SelectAiRule[]> {
      const rows = await db
        .select()
        .from(aiRules)
        .where(eq(aiRules.sombVersion, sombVersion));
      return rows;
    },

    // -----------------------------------------------------------------------
    // ai_provider_learning operations
    // -----------------------------------------------------------------------

    /**
     * Get learning state for a provider/rule pair. Returns null if not found.
     */
    async getLearningState(
      providerId: string,
      ruleId: string,
    ): Promise<SelectAiProviderLearning | null> {
      const rows = await db
        .select()
        .from(aiProviderLearning)
        .where(
          and(
            eq(aiProviderLearning.providerId, providerId),
            eq(aiProviderLearning.ruleId, ruleId),
          ),
        )
        .limit(1);
      return rows[0] ?? null;
    },

    /**
     * Get existing learning state or create a default one (lazy creation).
     */
    async getOrCreateLearningState(
      providerId: string,
      ruleId: string,
    ): Promise<SelectAiProviderLearning> {
      const existing = await db
        .select()
        .from(aiProviderLearning)
        .where(
          and(
            eq(aiProviderLearning.providerId, providerId),
            eq(aiProviderLearning.ruleId, ruleId),
          ),
        )
        .limit(1);

      if (existing[0]) {
        return existing[0];
      }

      const inserted = await db
        .insert(aiProviderLearning)
        .values({
          providerId,
          ruleId,
          timesShown: 0,
          timesAccepted: 0,
          timesDismissed: 0,
          consecutiveDismissals: 0,
          isSuppressed: false,
          priorityAdjustment: 0,
        })
        .returning();
      return inserted[0];
    },

    /**
     * Increment times_shown and set last_shown_at. Creates if not exists.
     */
    async incrementShown(
      providerId: string,
      ruleId: string,
    ): Promise<SelectAiProviderLearning> {
      // Ensure the row exists first
      const state = await this.getOrCreateLearningState(providerId, ruleId);

      const now = new Date();
      const rows = await db
        .update(aiProviderLearning)
        .set({
          timesShown: state.timesShown + 1,
          lastShownAt: now,
          updatedAt: now,
        })
        .where(
          and(
            eq(aiProviderLearning.providerId, providerId),
            eq(aiProviderLearning.ruleId, ruleId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Record acceptance: increment times_accepted, reset consecutive_dismissals,
     * unsuppress if suppressed, set last_feedback_at.
     */
    async recordAcceptance(
      providerId: string,
      ruleId: string,
    ): Promise<SelectAiProviderLearning> {
      const state = await this.getOrCreateLearningState(providerId, ruleId);

      const now = new Date();
      const rows = await db
        .update(aiProviderLearning)
        .set({
          timesAccepted: state.timesAccepted + 1,
          consecutiveDismissals: 0,
          isSuppressed: false,
          lastFeedbackAt: now,
          updatedAt: now,
        })
        .where(
          and(
            eq(aiProviderLearning.providerId, providerId),
            eq(aiProviderLearning.ruleId, ruleId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Record dismissal: increment times_dismissed and consecutive_dismissals.
     * Auto-suppress if consecutive_dismissals >= SUPPRESSION_THRESHOLD (5).
     */
    async recordDismissal(
      providerId: string,
      ruleId: string,
    ): Promise<SelectAiProviderLearning> {
      const state = await this.getOrCreateLearningState(providerId, ruleId);

      const newConsecutive = state.consecutiveDismissals + 1;
      const shouldSuppress = newConsecutive >= SUPPRESSION_THRESHOLD;
      const now = new Date();

      const rows = await db
        .update(aiProviderLearning)
        .set({
          timesDismissed: state.timesDismissed + 1,
          consecutiveDismissals: newConsecutive,
          isSuppressed: shouldSuppress || state.isSuppressed,
          lastFeedbackAt: now,
          updatedAt: now,
        })
        .where(
          and(
            eq(aiProviderLearning.providerId, providerId),
            eq(aiProviderLearning.ruleId, ruleId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Unsuppress a rule: set is_suppressed = false, reset consecutive_dismissals.
     */
    async unsuppressRule(
      providerId: string,
      ruleId: string,
    ): Promise<SelectAiProviderLearning | undefined> {
      const now = new Date();
      const rows = await db
        .update(aiProviderLearning)
        .set({
          isSuppressed: false,
          consecutiveDismissals: 0,
          updatedAt: now,
        })
        .where(
          and(
            eq(aiProviderLearning.providerId, providerId),
            eq(aiProviderLearning.ruleId, ruleId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * List all suppressed rules for a physician.
     */
    async getSuppressedRules(
      providerId: string,
    ): Promise<SelectAiProviderLearning[]> {
      const rows = await db
        .select()
        .from(aiProviderLearning)
        .where(
          and(
            eq(aiProviderLearning.providerId, providerId),
            eq(aiProviderLearning.isSuppressed, true),
          ),
        );
      return rows;
    },

    /**
     * Aggregate learning summary for a physician:
     * suppressed_count, top_accepted_categories (top 3), total shown, overall acceptance rate.
     */
    async getLearningStateSummary(
      providerId: string,
    ): Promise<LearningStateSummary> {
      // Get all learning states for this provider with joined rule category
      const rows = await db
        .select({
          ruleId: aiProviderLearning.ruleId,
          timesShown: aiProviderLearning.timesShown,
          timesAccepted: aiProviderLearning.timesAccepted,
          isSuppressed: aiProviderLearning.isSuppressed,
          category: aiRules.category,
        })
        .from(aiProviderLearning)
        .innerJoin(aiRules, eq(aiProviderLearning.ruleId, aiRules.ruleId))
        .where(eq(aiProviderLearning.providerId, providerId));

      let suppressedCount = 0;
      let totalShown = 0;
      let totalAccepted = 0;
      const categoryAccepted: Record<string, number> = {};

      for (const row of rows) {
        if (row.isSuppressed) suppressedCount++;
        totalShown += row.timesShown;
        totalAccepted += row.timesAccepted;
        if (row.category && row.timesAccepted > 0) {
          categoryAccepted[row.category] =
            (categoryAccepted[row.category] ?? 0) + row.timesAccepted;
        }
      }

      const topAcceptedCategories = Object.entries(categoryAccepted)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([category, acceptedCount]) => ({ category, acceptedCount }));

      return {
        suppressedCount,
        topAcceptedCategories,
        totalSuggestionsShown: totalShown,
        overallAcceptanceRate: totalShown > 0 ? totalAccepted / totalShown : 0,
      };
    },

    /**
     * Batch fetch learning states for multiple rules.
     * Used during Tier 1 evaluation to check suppression.
     */
    async getProviderLearningForRules(
      providerId: string,
      ruleIds: string[],
    ): Promise<SelectAiProviderLearning[]> {
      if (ruleIds.length === 0) return [];

      const rows = await db
        .select()
        .from(aiProviderLearning)
        .where(
          and(
            eq(aiProviderLearning.providerId, providerId),
            inArray(aiProviderLearning.ruleId, ruleIds),
          ),
        );
      return rows;
    },

    /**
     * Set priority_adjustment for a provider/rule pair.
     * Derived from acceptance rate thresholds:
     * >70% accepted -> +1, <30% accepted -> -1, else 0.
     */
    async updatePriorityAdjustment(
      providerId: string,
      ruleId: string,
      adjustment: -1 | 0 | 1,
    ): Promise<SelectAiProviderLearning | undefined> {
      const now = new Date();
      const rows = await db
        .update(aiProviderLearning)
        .set({
          priorityAdjustment: adjustment,
          updatedAt: now,
        })
        .where(
          and(
            eq(aiProviderLearning.providerId, providerId),
            eq(aiProviderLearning.ruleId, ruleId),
          ),
        )
        .returning();
      return rows[0];
    },

    // -----------------------------------------------------------------------
    // ai_specialty_cohorts operations
    // -----------------------------------------------------------------------

    /**
     * Get cohort defaults for a specialty + rule pair.
     * Returns null if physician_count < MIN_COHORT_SIZE (10) to prevent
     * de-identification of small cohorts.
     */
    async getCohortDefaults(
      specialtyCode: string,
      ruleId: string,
    ): Promise<SelectAiSpecialtyCohort | null> {
      const rows = await db
        .select()
        .from(aiSpecialtyCohorts)
        .where(
          and(
            eq(aiSpecialtyCohorts.specialtyCode, specialtyCode),
            eq(aiSpecialtyCohorts.ruleId, ruleId),
            gte(aiSpecialtyCohorts.physicianCount, MIN_COHORT_SIZE),
          ),
        )
        .limit(1);
      return rows[0] ?? null;
    },

    /**
     * Insert or update a cohort aggregate for a specialty + rule pair.
     * Called by the nightly recalculation job.
     */
    async upsertCohortAggregate(
      specialtyCode: string,
      ruleId: string,
      data: CohortAggregateInput,
    ): Promise<SelectAiSpecialtyCohort> {
      const existing = await db
        .select()
        .from(aiSpecialtyCohorts)
        .where(
          and(
            eq(aiSpecialtyCohorts.specialtyCode, specialtyCode),
            eq(aiSpecialtyCohorts.ruleId, ruleId),
          ),
        )
        .limit(1);

      if (existing[0]) {
        const updated = await db
          .update(aiSpecialtyCohorts)
          .set({
            physicianCount: data.physicianCount,
            acceptanceRate: data.acceptanceRate,
            medianRevenueImpact: data.medianRevenueImpact ?? null,
            updatedAt: new Date(),
          })
          .where(eq(aiSpecialtyCohorts.cohortId, existing[0].cohortId))
          .returning();
        return updated[0];
      }

      const inserted = await db
        .insert(aiSpecialtyCohorts)
        .values({
          specialtyCode,
          ruleId,
          physicianCount: data.physicianCount,
          acceptanceRate: data.acceptanceRate,
          medianRevenueImpact: data.medianRevenueImpact ?? null,
        })
        .returning();
      return inserted[0];
    },

    /**
     * Recalculate all cohort aggregates from ai_provider_learning.
     * Groups by provider specialty (joined from providers table) and rule_id.
     * Computes acceptance_rate = SUM(times_accepted) / SUM(times_shown).
     * Computes median_revenue_impact from ai_suggestion_events for ACCEPTED events.
     * Only includes cohorts where physician_count >= MIN_COHORT_SIZE (10).
     */
    async recalculateAllCohorts(): Promise<SelectAiSpecialtyCohort[]> {
      // Aggregate learning data grouped by specialty + rule
      const aggregates = await db
        .select({
          specialtyCode: providers.specialtyCode,
          ruleId: aiProviderLearning.ruleId,
          physicianCount: sql<number>`COUNT(DISTINCT ${aiProviderLearning.providerId})::int`,
          totalShown: sql<number>`COALESCE(SUM(${aiProviderLearning.timesShown}), 0)::int`,
          totalAccepted: sql<number>`COALESCE(SUM(${aiProviderLearning.timesAccepted}), 0)::int`,
        })
        .from(aiProviderLearning)
        .innerJoin(providers, eq(aiProviderLearning.providerId, providers.providerId))
        .groupBy(providers.specialtyCode, aiProviderLearning.ruleId);

      const results: SelectAiSpecialtyCohort[] = [];

      for (const agg of aggregates) {
        const physicianCount = Number(agg.physicianCount);
        if (physicianCount < MIN_COHORT_SIZE) continue;

        const totalShown = Number(agg.totalShown);
        const totalAccepted = Number(agg.totalAccepted);
        const acceptanceRate = totalShown > 0 ? totalAccepted / totalShown : 0;

        // Compute median revenue impact from accepted suggestion events
        const revenueRows = await db
          .select({ revenueImpact: aiSuggestionEvents.revenueImpact })
          .from(aiSuggestionEvents)
          .innerJoin(providers, eq(aiSuggestionEvents.providerId, providers.providerId))
          .where(
            and(
              eq(providers.specialtyCode, agg.specialtyCode),
              eq(aiSuggestionEvents.ruleId, agg.ruleId),
              eq(aiSuggestionEvents.eventType, 'ACCEPTED'),
            ),
          );

        const impacts = revenueRows
          .map((r) => parseFloat(r.revenueImpact ?? '0'))
          .filter((v) => !isNaN(v))
          .sort((a, b) => a - b);

        let medianRevenueImpact: string | null = null;
        if (impacts.length > 0) {
          const mid = Math.floor(impacts.length / 2);
          const median =
            impacts.length % 2 === 0
              ? (impacts[mid - 1] + impacts[mid]) / 2
              : impacts[mid];
          medianRevenueImpact = median.toFixed(2);
        }

        const cohort = await this.upsertCohortAggregate(
          agg.specialtyCode,
          agg.ruleId,
          {
            physicianCount,
            acceptanceRate: acceptanceRate.toFixed(4),
            medianRevenueImpact,
          },
        );
        results.push(cohort);
      }

      return results;
    },

    /**
     * List cohorts with optional filters for admin review.
     */
    async listCohorts(
      filters: CohortListFilters,
    ): Promise<SelectAiSpecialtyCohort[]> {
      const conditions: any[] = [];

      if (filters.specialtyCode !== undefined) {
        conditions.push(eq(aiSpecialtyCohorts.specialtyCode, filters.specialtyCode));
      }

      if (filters.ruleId !== undefined) {
        conditions.push(eq(aiSpecialtyCohorts.ruleId, filters.ruleId));
      }

      const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

      const rows = await db
        .select()
        .from(aiSpecialtyCohorts)
        .where(whereClause!)
        .orderBy(desc(aiSpecialtyCohorts.updatedAt));
      return rows;
    },

    // -----------------------------------------------------------------------
    // ai_suggestion_events operations (APPEND-ONLY)
    // -----------------------------------------------------------------------

    /**
     * Append a single suggestion event. This is the ONLY write operation
     * on ai_suggestion_events. No UPDATE or DELETE functions exist.
     */
    async appendSuggestionEvent(
      event: SuggestionEventInput,
    ): Promise<SelectAiSuggestionEvent> {
      const rows = await db
        .insert(aiSuggestionEvents)
        .values({
          claimId: event.claimId,
          suggestionId: event.suggestionId,
          ruleId: event.ruleId ?? null,
          providerId: event.providerId,
          eventType: event.eventType,
          tier: event.tier,
          category: event.category,
          revenueImpact: event.revenueImpact ?? null,
          dismissedReason: event.dismissedReason ?? null,
        })
        .returning();
      return rows[0];
    },

    /**
     * Get all suggestion events for a claim, ordered chronologically (oldest first).
     */
    async getSuggestionEventsForClaim(
      claimId: string,
    ): Promise<SelectAiSuggestionEvent[]> {
      const rows = await db
        .select()
        .from(aiSuggestionEvents)
        .where(eq(aiSuggestionEvents.claimId, claimId))
        .orderBy(asc(aiSuggestionEvents.createdAt));
      return rows;
    },

    /**
     * Get suggestion events for a provider with filters, paginated, reverse chronological.
     */
    async getSuggestionEventsForProvider(
      providerId: string,
      filters: ProviderEventFilters,
    ): Promise<PaginatedResult<SelectAiSuggestionEvent>> {
      const conditions: any[] = [
        eq(aiSuggestionEvents.providerId, providerId),
      ];

      if (filters.category !== undefined) {
        conditions.push(eq(aiSuggestionEvents.category, filters.category));
      }
      if (filters.tier !== undefined) {
        conditions.push(eq(aiSuggestionEvents.tier, filters.tier));
      }
      if (filters.eventType !== undefined) {
        conditions.push(eq(aiSuggestionEvents.eventType, filters.eventType));
      }
      if (filters.startDate !== undefined) {
        conditions.push(gte(aiSuggestionEvents.createdAt, new Date(filters.startDate)));
      }
      if (filters.endDate !== undefined) {
        conditions.push(lte(aiSuggestionEvents.createdAt, new Date(filters.endDate)));
      }

      const whereClause = and(...conditions);
      const offset = (filters.page - 1) * filters.pageSize;

      const [countResult, rows] = await Promise.all([
        db
          .select({ total: count() })
          .from(aiSuggestionEvents)
          .where(whereClause!),
        db
          .select()
          .from(aiSuggestionEvents)
          .where(whereClause!)
          .orderBy(desc(aiSuggestionEvents.createdAt))
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
     * Look up the claim_id for a suggestion by finding the first GENERATED event
     * with that suggestion_id. Used by accept/dismiss handlers that receive
     * only a suggestion_id in the URL.
     */
    async findClaimIdBySuggestionId(
      suggestionId: string,
    ): Promise<string | null> {
      const rows = await db
        .select({ claimId: aiSuggestionEvents.claimId })
        .from(aiSuggestionEvents)
        .where(
          and(
            eq(aiSuggestionEvents.suggestionId, suggestionId),
            eq(aiSuggestionEvents.eventType, 'GENERATED'),
          ),
        )
        .limit(1);
      return rows[0]?.claimId ?? null;
    },

    /**
     * Get suggestion events for a rule with optional filters.
     * Used for the rule stats dashboard.
     */
    async getRulePerformanceEvents(
      ruleId: string,
      filters: RulePerformanceFilters,
    ): Promise<SelectAiSuggestionEvent[]> {
      const conditions: any[] = [
        eq(aiSuggestionEvents.ruleId, ruleId),
      ];

      if (filters.eventType !== undefined) {
        conditions.push(eq(aiSuggestionEvents.eventType, filters.eventType));
      }
      if (filters.startDate !== undefined) {
        conditions.push(gte(aiSuggestionEvents.createdAt, new Date(filters.startDate)));
      }
      if (filters.endDate !== undefined) {
        conditions.push(lte(aiSuggestionEvents.createdAt, new Date(filters.endDate)));
      }

      const whereClause = and(...conditions);

      const rows = await db
        .select()
        .from(aiSuggestionEvents)
        .where(whereClause!)
        .orderBy(desc(aiSuggestionEvents.createdAt));
      return rows;
    },
  };
}

// ---------------------------------------------------------------------------
// Export types
// ---------------------------------------------------------------------------

export type IntelRepository = ReturnType<typeof createIntelRepository>;
