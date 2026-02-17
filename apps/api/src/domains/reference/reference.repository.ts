import { eq, and, lte, gte, isNull, or, desc, asc, sql } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  referenceDataVersions,
  hscCodes,
  wcbCodes,
  modifierDefinitions,
  governingRules,
  diCodes,
  rrnpCommunities,
  pcpcmBaskets,
  functionalCentres,
  statutoryHolidays,
  explanatoryCodes,
  referenceDataStaging,
  type InsertVersion,
  type SelectVersion,
  type SelectHscCode,
  type InsertHscCode,
  type SelectWcbCode,
  type InsertWcbCode,
  type SelectModifierDefinition,
  type InsertModifierDefinition,
  type SelectGoverningRule,
  type InsertGoverningRule,
  type SelectDiCode,
  type InsertDiCode,
  type SelectRrnpCommunity,
  type InsertRrnpCommunity,
  type SelectPcpcmBasket,
  type InsertPcpcmBasket,
  type SelectFunctionalCentre,
  type InsertFunctionalCentre,
  type SelectStatutoryHoliday,
  type InsertStatutoryHoliday,
  type SelectExplanatoryCode,
  type InsertExplanatoryCode,
  type SelectReferenceDataStaging,
} from '@meritum/shared/schemas/db/reference.schema.js';

// ---------------------------------------------------------------------------
// Reference Data Repository — Version Management + HSC Code Queries
// ---------------------------------------------------------------------------

export function createReferenceRepository(db: NodePgDatabase) {
  return {
    // -----------------------------------------------------------------------
    // Version Management
    // -----------------------------------------------------------------------

    /**
     * Find the currently active version for a data set.
     * At most one version per data_set may be active (enforced by partial unique index).
     */
    async findActiveVersion(dataSet: string): Promise<SelectVersion | undefined> {
      const rows = await db
        .select()
        .from(referenceDataVersions)
        .where(
          and(
            eq(referenceDataVersions.dataSet, dataSet),
            eq(referenceDataVersions.isActive, true),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * Find the version effective on a specific date for a data set.
     * Logic: effectiveFrom <= date AND (effectiveTo IS NULL OR effectiveTo > date)
     *
     * Critical: claim on effectiveFrom date uses the new version.
     * Claim on the day before effectiveFrom uses the old version.
     */
    async findVersionForDate(
      dataSet: string,
      date: Date,
    ): Promise<SelectVersion | undefined> {
      const dateStr = date.toISOString().split('T')[0];
      const rows = await db
        .select()
        .from(referenceDataVersions)
        .where(
          and(
            eq(referenceDataVersions.dataSet, dataSet),
            lte(referenceDataVersions.effectiveFrom, dateStr),
            or(
              isNull(referenceDataVersions.effectiveTo),
              sql`${referenceDataVersions.effectiveTo} > ${dateStr}`,
            ),
          ),
        )
        .orderBy(desc(referenceDataVersions.effectiveFrom))
        .limit(1);
      return rows[0];
    },

    /**
     * List all versions for a data set, ordered by effectiveFrom DESC.
     */
    async listVersions(dataSet: string): Promise<SelectVersion[]> {
      return db
        .select()
        .from(referenceDataVersions)
        .where(eq(referenceDataVersions.dataSet, dataSet))
        .orderBy(desc(referenceDataVersions.effectiveFrom));
    },

    /**
     * Insert a new version record.
     */
    async createVersion(data: InsertVersion): Promise<SelectVersion> {
      const rows = await db
        .insert(referenceDataVersions)
        .values(data)
        .returning();
      return rows[0];
    },

    /**
     * Atomically activate a version and optionally deactivate the previous one.
     * If previousVersionId is provided, set its isActive=false and effectiveTo
     * to the new version's effectiveFrom.
     *
     * CRITICAL: At no point should two versions be active simultaneously
     * for the same data set. Deactivate previous BEFORE activating new.
     */
    async activateVersion(
      versionId: string,
      previousVersionId?: string,
    ): Promise<void> {
      // Get the new version's effectiveFrom for setting the previous version's effectiveTo
      const newVersionRows = await db
        .select()
        .from(referenceDataVersions)
        .where(eq(referenceDataVersions.versionId, versionId))
        .limit(1);

      const newVersion = newVersionRows[0];
      if (!newVersion) {
        throw new Error('Version not found');
      }

      if (previousVersionId) {
        // Deactivate previous version and set its effectiveTo
        await db
          .update(referenceDataVersions)
          .set({
            isActive: false,
            effectiveTo: newVersion.effectiveFrom,
          })
          .where(eq(referenceDataVersions.versionId, previousVersionId));
      }

      // Activate new version
      await db
        .update(referenceDataVersions)
        .set({ isActive: true })
        .where(eq(referenceDataVersions.versionId, versionId));
    },

    /**
     * Rollback: set isActive=false on a version.
     */
    async deactivateVersion(versionId: string): Promise<void> {
      await db
        .update(referenceDataVersions)
        .set({ isActive: false })
        .where(eq(referenceDataVersions.versionId, versionId));
    },

    // -----------------------------------------------------------------------
    // HSC Code Queries
    // -----------------------------------------------------------------------

    /**
     * Full-text + pg_trgm search on hsc_code and description.
     * Filter by version_id. Optionally filter by specialty_restrictions
     * and facility_restrictions JSONB contains.
     * Returns summary fields ordered by relevance.
     */
    async searchHscCodes(
      query: string,
      versionId: string,
      filters?: { specialty?: string; facility?: string },
      limit: number = 20,
    ): Promise<
      Pick<
        SelectHscCode,
        'id' | 'hscCode' | 'description' | 'baseFee' | 'feeType' | 'helpText' | 'effectiveTo'
      >[]
    > {
      const conditions = [eq(hscCodes.versionId, versionId)];

      if (filters?.specialty) {
        conditions.push(
          sql`${hscCodes.specialtyRestrictions} @> ${JSON.stringify([filters.specialty])}::jsonb`,
        );
      }

      if (filters?.facility) {
        conditions.push(
          sql`${hscCodes.facilityRestrictions} @> ${JSON.stringify([filters.facility])}::jsonb`,
        );
      }

      // Combine full-text search (ts_rank) with trigram similarity for relevance ranking
      const rows = await db
        .select({
          id: hscCodes.id,
          hscCode: hscCodes.hscCode,
          description: hscCodes.description,
          baseFee: hscCodes.baseFee,
          feeType: hscCodes.feeType,
          helpText: hscCodes.helpText,
          effectiveTo: hscCodes.effectiveTo,
        })
        .from(hscCodes)
        .where(
          and(
            ...conditions,
            or(
              sql`${hscCodes.hscCode} ILIKE ${`%${query}%`}`,
              sql`to_tsvector('english', ${hscCodes.description}) @@ plainto_tsquery('english', ${query})`,
              sql`similarity(${hscCodes.description}, ${query}) > 0.1`,
            ),
          ),
        )
        .orderBy(
          sql`GREATEST(
            similarity(${hscCodes.hscCode}, ${query}),
            similarity(${hscCodes.description}, ${query}),
            ts_rank(to_tsvector('english', ${hscCodes.description}), plainto_tsquery('english', ${query}))
          ) DESC`,
        )
        .limit(limit);

      return rows;
    },

    /**
     * Full detail for a single HSC code by code string and version.
     * Returns all fields including modifiers, restrictions, combination_group, etc.
     */
    async findHscByCode(
      hscCode: string,
      versionId: string,
    ): Promise<SelectHscCode | undefined> {
      const rows = await db
        .select()
        .from(hscCodes)
        .where(
          and(
            eq(hscCodes.hscCode, hscCode),
            eq(hscCodes.versionId, versionId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * List all HSC codes for a version with pagination (admin use).
     */
    async listHscByVersion(
      versionId: string,
      pagination: { limit: number; offset: number },
    ): Promise<{ data: SelectHscCode[]; total: number }> {
      const data = await db
        .select()
        .from(hscCodes)
        .where(eq(hscCodes.versionId, versionId))
        .limit(pagination.limit)
        .offset(pagination.offset);

      const countResult = await db
        .select({ count: sql<number>`count(*)::int` })
        .from(hscCodes)
        .where(eq(hscCodes.versionId, versionId));

      const total = countResult[0]?.count ?? 0;

      return { data, total };
    },

    // -----------------------------------------------------------------------
    // WCB Code Queries
    // -----------------------------------------------------------------------

    /**
     * Full-text + pg_trgm search on wcb_code and description.
     * Filter by version_id. Returns summary fields ordered by relevance.
     */
    async searchWcbCodes(
      query: string,
      versionId: string,
      limit: number = 20,
    ): Promise<
      Pick<
        SelectWcbCode,
        'id' | 'wcbCode' | 'description' | 'baseFee' | 'feeType' | 'helpText'
      >[]
    > {
      const rows = await db
        .select({
          id: wcbCodes.id,
          wcbCode: wcbCodes.wcbCode,
          description: wcbCodes.description,
          baseFee: wcbCodes.baseFee,
          feeType: wcbCodes.feeType,
          helpText: wcbCodes.helpText,
        })
        .from(wcbCodes)
        .where(
          and(
            eq(wcbCodes.versionId, versionId),
            or(
              sql`${wcbCodes.wcbCode} ILIKE ${`%${query}%`}`,
              sql`to_tsvector('english', ${wcbCodes.description}) @@ plainto_tsquery('english', ${query})`,
              sql`similarity(${wcbCodes.description}, ${query}) > 0.1`,
            ),
          ),
        )
        .orderBy(
          sql`GREATEST(
            similarity(${wcbCodes.wcbCode}, ${query}),
            similarity(${wcbCodes.description}, ${query}),
            ts_rank(to_tsvector('english', ${wcbCodes.description}), plainto_tsquery('english', ${query}))
          ) DESC`,
        )
        .limit(limit);

      return rows;
    },

    /**
     * Full detail for a single WCB code by code string and version.
     * Returns all fields including requires_claim_number, requires_employer,
     * documentation_requirements, help_text. Single record or null.
     */
    async findWcbByCode(
      wcbCode: string,
      versionId: string,
    ): Promise<SelectWcbCode | undefined> {
      const rows = await db
        .select()
        .from(wcbCodes)
        .where(
          and(
            eq(wcbCodes.wcbCode, wcbCode),
            eq(wcbCodes.versionId, versionId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    // -----------------------------------------------------------------------
    // Modifier Definition Queries
    // -----------------------------------------------------------------------

    /**
     * Find applicable modifiers for a given HSC code based on
     * applicable_hsc_filter JSONB matching. Filter by version_id.
     *
     * Matching logic: a modifier is applicable if its applicable_hsc_filter
     * contains the hscCode in its "codes" array, or the hscCode starts with
     * any prefix in its "prefixes" array, or the filter specifies "all": true.
     */
    async findModifiersForHsc(
      hscCode: string,
      versionId: string,
    ): Promise<SelectModifierDefinition[]> {
      // Fetch all modifiers for this version, then filter in application code
      // because JSONB filter matching requires complex logic (codes array,
      // prefixes array, all flag) that's cleaner to express in TypeScript.
      const allModifiers = await db
        .select()
        .from(modifierDefinitions)
        .where(eq(modifierDefinitions.versionId, versionId));

      return allModifiers.filter((mod) => {
        const filter = mod.applicableHscFilter as Record<string, unknown>;
        if (!filter) return false;

        // "all": true means applicable to every HSC code
        if (filter.all === true) return true;

        // Check "codes" array for exact match
        const codes = filter.codes;
        if (Array.isArray(codes) && codes.includes(hscCode)) return true;

        // Check "prefixes" array for prefix match
        const prefixes = filter.prefixes;
        if (Array.isArray(prefixes) && prefixes.some((p: string) => hscCode.startsWith(p))) return true;

        return false;
      });
    },

    /**
     * Full detail for a single modifier by modifier code and version.
     * Returns all fields including combinable_with, exclusive_with,
     * calculation_params, governing_rule_reference.
     */
    async findModifierByCode(
      modifierCode: string,
      versionId: string,
    ): Promise<SelectModifierDefinition | undefined> {
      const rows = await db
        .select()
        .from(modifierDefinitions)
        .where(
          and(
            eq(modifierDefinitions.modifierCode, modifierCode),
            eq(modifierDefinitions.versionId, versionId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * List all modifiers for a version.
     */
    async listAllModifiers(
      versionId: string,
    ): Promise<SelectModifierDefinition[]> {
      return db
        .select()
        .from(modifierDefinitions)
        .where(eq(modifierDefinitions.versionId, versionId));
    },

    // -----------------------------------------------------------------------
    // Governing Rules Queries
    // -----------------------------------------------------------------------

    /**
     * Find all rules applicable to a claim context.
     * Match rules where rule_logic JSONB references any of the provided
     * HSC codes, DI code, or facility type. Also return rules in "general" category.
     *
     * rule_logic is data only — it is never evaluated here.
     * The Claim Lifecycle validation engine evaluates it.
     */
    async findRulesForContext(
      hscCodes_: string[],
      diCode: string | null,
      facilityType: string | null,
      versionId: string,
    ): Promise<SelectGoverningRule[]> {
      // Fetch all rules for this version, then filter in application code
      // because rule_logic JSONB matching requires inspecting nested JSON
      // structures for HSC codes, DI codes, and facility types.
      const allRules = await db
        .select()
        .from(governingRules)
        .where(eq(governingRules.versionId, versionId));

      return allRules.filter((rule) => {
        // General rules always apply
        if (rule.ruleCategory === 'general') return true;

        const logic = rule.ruleLogic as Record<string, unknown>;
        if (!logic) return false;

        const logicStr = JSON.stringify(logic);

        // Check if rule references any of the provided HSC codes
        if (hscCodes_.some((code) => logicStr.includes(code))) return true;

        // Check if rule references the DI code
        if (diCode && logicStr.includes(diCode)) return true;

        // Check if rule references the facility type
        if (facilityType && logicStr.includes(facilityType)) return true;

        return false;
      });
    },

    /**
     * Full detail for a single governing rule by ID and version.
     * Returns all fields including rule_logic JSON.
     */
    async findRuleById(
      ruleId: string,
      versionId: string,
    ): Promise<SelectGoverningRule | undefined> {
      const rows = await db
        .select()
        .from(governingRules)
        .where(
          and(
            eq(governingRules.ruleId, ruleId),
            eq(governingRules.versionId, versionId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * List all rules in a category for a version.
     */
    async listRulesByCategory(
      category: string,
      versionId: string,
    ): Promise<SelectGoverningRule[]> {
      return db
        .select()
        .from(governingRules)
        .where(
          and(
            eq(governingRules.ruleCategory, category),
            eq(governingRules.versionId, versionId),
          ),
        );
    },

    // -----------------------------------------------------------------------
    // DI Code Queries
    // -----------------------------------------------------------------------

    /**
     * Full-text + pg_trgm search on di_code and description.
     * If specialty provided, boost results where common_in_specialty JSONB
     * contains the specialty (specialty-weighted results first).
     */
    async searchDiCodes(
      query: string,
      versionId: string,
      filters?: { specialty?: string },
      limit: number = 20,
    ): Promise<
      Pick<
        SelectDiCode,
        'id' | 'diCode' | 'description' | 'category' | 'qualifiesSurcharge' | 'qualifiesBcp' | 'helpText'
      >[]
    > {
      const conditions = [eq(diCodes.versionId, versionId)];

      const specialtyBoost = filters?.specialty
        ? sql`CASE WHEN ${diCodes.commonInSpecialty} @> ${JSON.stringify([filters.specialty])}::jsonb THEN 1 ELSE 0 END`
        : sql`0`;

      const rows = await db
        .select({
          id: diCodes.id,
          diCode: diCodes.diCode,
          description: diCodes.description,
          category: diCodes.category,
          qualifiesSurcharge: diCodes.qualifiesSurcharge,
          qualifiesBcp: diCodes.qualifiesBcp,
          helpText: diCodes.helpText,
        })
        .from(diCodes)
        .where(
          and(
            ...conditions,
            or(
              sql`${diCodes.diCode} ILIKE ${`%${query}%`}`,
              sql`to_tsvector('english', ${diCodes.description}) @@ plainto_tsquery('english', ${query})`,
              sql`similarity(${diCodes.description}, ${query}) > 0.1`,
            ),
          ),
        )
        .orderBy(
          sql`${specialtyBoost} DESC`,
          sql`GREATEST(
            similarity(${diCodes.diCode}, ${query}),
            similarity(${diCodes.description}, ${query}),
            ts_rank(to_tsvector('english', ${diCodes.description}), plainto_tsquery('english', ${query}))
          ) DESC`,
        )
        .limit(limit);

      return rows;
    },

    /**
     * Full detail for a single DI code by code string and version.
     * Returns all fields including subcategory, surcharge/BCP flags, common_in_specialty.
     */
    async findDiByCode(
      diCode: string,
      versionId: string,
    ): Promise<SelectDiCode | undefined> {
      const rows = await db
        .select()
        .from(diCodes)
        .where(
          and(
            eq(diCodes.diCode, diCode),
            eq(diCodes.versionId, versionId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    // -----------------------------------------------------------------------
    // RRNP Community Queries
    // -----------------------------------------------------------------------

    /**
     * Return community_name and rrnp_percentage for a specific community and version.
     */
    async findRrnpRate(
      communityId: string,
      versionId: string,
    ): Promise<Pick<SelectRrnpCommunity, 'communityName' | 'rrnpPercentage'> | undefined> {
      const rows = await db
        .select({
          communityName: rrnpCommunities.communityName,
          rrnpPercentage: rrnpCommunities.rrnpPercentage,
        })
        .from(rrnpCommunities)
        .where(
          and(
            eq(rrnpCommunities.communityId, communityId),
            eq(rrnpCommunities.versionId, versionId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * All communities for a version, ordered by community_name.
     */
    async listRrnpCommunities(
      versionId: string,
    ): Promise<SelectRrnpCommunity[]> {
      return db
        .select()
        .from(rrnpCommunities)
        .where(eq(rrnpCommunities.versionId, versionId))
        .orderBy(asc(rrnpCommunities.communityName));
    },

    // -----------------------------------------------------------------------
    // PCPCM Basket Queries
    // -----------------------------------------------------------------------

    /**
     * Return basket classification for an HSC code and version.
     */
    async findPcpcmBasket(
      hscCode: string,
      versionId: string,
    ): Promise<SelectPcpcmBasket | undefined> {
      const rows = await db
        .select()
        .from(pcpcmBaskets)
        .where(
          and(
            eq(pcpcmBaskets.hscCode, hscCode),
            eq(pcpcmBaskets.versionId, versionId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    // -----------------------------------------------------------------------
    // Functional Centre Queries
    // -----------------------------------------------------------------------

    /**
     * List functional centres for a version. Optionally filter by facility_type.
     */
    async listFunctionalCentres(
      versionId: string,
      facilityType?: string,
    ): Promise<
      Pick<
        SelectFunctionalCentre,
        'code' | 'name' | 'facilityType' | 'locationCity' | 'locationRegion' | 'active'
      >[]
    > {
      const conditions = [eq(functionalCentres.versionId, versionId)];

      if (facilityType) {
        conditions.push(eq(functionalCentres.facilityType, facilityType));
      }

      return db
        .select({
          code: functionalCentres.code,
          name: functionalCentres.name,
          facilityType: functionalCentres.facilityType,
          locationCity: functionalCentres.locationCity,
          locationRegion: functionalCentres.locationRegion,
          active: functionalCentres.active,
        })
        .from(functionalCentres)
        .where(and(...conditions));
    },

    /**
     * Single centre detail including rrnp_community_id.
     */
    async findFunctionalCentre(
      code: string,
      versionId: string,
    ): Promise<SelectFunctionalCentre | undefined> {
      const rows = await db
        .select()
        .from(functionalCentres)
        .where(
          and(
            eq(functionalCentres.code, code),
            eq(functionalCentres.versionId, versionId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    // -----------------------------------------------------------------------
    // Statutory Holiday Queries
    // -----------------------------------------------------------------------

    /**
     * Return all holidays for a given year, ordered by date.
     */
    async listHolidaysByYear(
      year: number,
    ): Promise<SelectStatutoryHoliday[]> {
      return db
        .select()
        .from(statutoryHolidays)
        .where(eq(statutoryHolidays.year, year))
        .orderBy(asc(statutoryHolidays.date));
    },

    /**
     * Check if a specific date is a statutory holiday.
     */
    async isHoliday(
      date: Date,
    ): Promise<{
      is_holiday: boolean;
      holiday_name?: string;
      jurisdiction?: string;
      affects_billing_premiums?: boolean;
    }> {
      const dateStr = date.toISOString().split('T')[0];
      const rows = await db
        .select()
        .from(statutoryHolidays)
        .where(eq(statutoryHolidays.date, dateStr))
        .limit(1);

      if (rows.length === 0) {
        return { is_holiday: false };
      }

      return {
        is_holiday: true,
        holiday_name: rows[0].name,
        jurisdiction: rows[0].jurisdiction,
        affects_billing_premiums: rows[0].affectsBillingPremiums,
      };
    },

    /**
     * Insert a new holiday record.
     */
    async createHoliday(
      data: InsertStatutoryHoliday,
    ): Promise<SelectStatutoryHoliday> {
      const rows = await db
        .insert(statutoryHolidays)
        .values(data)
        .returning();
      return rows[0];
    },

    /**
     * Update holiday fields.
     */
    async updateHoliday(
      holidayId: string,
      data: Partial<InsertStatutoryHoliday>,
    ): Promise<SelectStatutoryHoliday | undefined> {
      const rows = await db
        .update(statutoryHolidays)
        .set(data)
        .where(eq(statutoryHolidays.holidayId, holidayId))
        .returning();
      return rows[0];
    },

    /**
     * Remove holiday record.
     */
    async deleteHoliday(
      holidayId: string,
    ): Promise<void> {
      await db
        .delete(statutoryHolidays)
        .where(eq(statutoryHolidays.holidayId, holidayId));
    },

    // -----------------------------------------------------------------------
    // Explanatory Code Queries
    // -----------------------------------------------------------------------

    /**
     * Full detail for a single explanatory code including common_cause and suggested_action.
     */
    async findExplanatoryCode(
      code: string,
      versionId: string,
    ): Promise<SelectExplanatoryCode | undefined> {
      const rows = await db
        .select()
        .from(explanatoryCodes)
        .where(
          and(
            eq(explanatoryCodes.explCode, code),
            eq(explanatoryCodes.versionId, versionId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    // -----------------------------------------------------------------------
    // Staging Operations
    // -----------------------------------------------------------------------

    /**
     * Insert a staging record with status='uploaded'.
     */
    async createStagingRecord(data: {
      dataSet: string;
      uploadedBy: string;
      fileHash: string;
      recordCount: number;
      stagedData: unknown;
    }): Promise<SelectReferenceDataStaging> {
      const rows = await db
        .insert(referenceDataStaging)
        .values({
          dataSet: data.dataSet,
          uploadedBy: data.uploadedBy,
          fileHash: data.fileHash,
          recordCount: data.recordCount,
          stagedData: data.stagedData as Record<string, unknown>[],
          status: 'uploaded',
          uploadedAt: new Date(),
        })
        .returning();
      return rows[0];
    },

    /**
     * Find staging record by ID. Returns full record including staged_data JSONB.
     */
    async findStagingById(
      stagingId: string,
    ): Promise<SelectReferenceDataStaging | undefined> {
      const rows = await db
        .select()
        .from(referenceDataStaging)
        .where(eq(referenceDataStaging.stagingId, stagingId))
        .limit(1);
      return rows[0];
    },

    /**
     * Update staging status and optionally set validation_result or diff_result.
     * Valid transitions: uploaded -> validated, validated -> diff_generated,
     * diff_generated -> published, any -> discarded.
     */
    async updateStagingStatus(
      stagingId: string,
      status: string,
      result?: { validation_result?: unknown; diff_result?: unknown },
    ): Promise<SelectReferenceDataStaging | undefined> {
      const setClauses: Record<string, unknown> = { status };
      if (result?.validation_result !== undefined) {
        setClauses.validationResult = result.validation_result;
      }
      if (result?.diff_result !== undefined) {
        setClauses.diffResult = result.diff_result;
      }

      const rows = await db
        .update(referenceDataStaging)
        .set(setClauses)
        .where(eq(referenceDataStaging.stagingId, stagingId))
        .returning();
      return rows[0];
    },

    /**
     * Permanently remove a staging record (for discard flow).
     */
    async deleteStagingRecord(stagingId: string): Promise<void> {
      await db
        .delete(referenceDataStaging)
        .where(eq(referenceDataStaging.stagingId, stagingId));
    },

    /**
     * List pending staging records (status != 'published' and status != 'discarded')
     * for a data set, ordered by created_at DESC.
     */
    async listStagingByDataSet(
      dataSet: string,
    ): Promise<SelectReferenceDataStaging[]> {
      const rows = await db
        .select()
        .from(referenceDataStaging)
        .where(eq(referenceDataStaging.dataSet, dataSet))
        .orderBy(desc(referenceDataStaging.createdAt));

      return rows.filter(
        (row) => row.status !== 'published' && row.status !== 'discarded',
      );
    },

    // -----------------------------------------------------------------------
    // Bulk Data Operations (for publishing)
    // -----------------------------------------------------------------------

    /**
     * Batch insert HSC codes. Set version_id on all records.
     * Runs within a single transaction.
     */
    async bulkInsertHscCodes(
      records: InsertHscCode[],
      versionId: string,
    ): Promise<void> {
      const tagged = records.map((r) => ({ ...r, versionId }));
      await db.transaction(async (tx) => {
        for (let i = 0; i < tagged.length; i += BULK_CHUNK_SIZE) {
          const chunk = tagged.slice(i, i + BULK_CHUNK_SIZE);
          await tx.insert(hscCodes).values(chunk);
        }
      });
    },

    /**
     * Batch insert WCB codes. Set version_id on all records.
     */
    async bulkInsertWcbCodes(
      records: InsertWcbCode[],
      versionId: string,
    ): Promise<void> {
      const tagged = records.map((r) => ({ ...r, versionId }));
      await db.transaction(async (tx) => {
        for (let i = 0; i < tagged.length; i += BULK_CHUNK_SIZE) {
          const chunk = tagged.slice(i, i + BULK_CHUNK_SIZE);
          await tx.insert(wcbCodes).values(chunk);
        }
      });
    },

    /**
     * Batch insert modifier definitions. Set version_id on all records.
     */
    async bulkInsertModifiers(
      records: InsertModifierDefinition[],
      versionId: string,
    ): Promise<void> {
      const tagged = records.map((r) => ({ ...r, versionId }));
      await db.transaction(async (tx) => {
        for (let i = 0; i < tagged.length; i += BULK_CHUNK_SIZE) {
          const chunk = tagged.slice(i, i + BULK_CHUNK_SIZE);
          await tx.insert(modifierDefinitions).values(chunk);
        }
      });
    },

    /**
     * Batch insert governing rules. Set version_id on all records.
     */
    async bulkInsertRules(
      records: InsertGoverningRule[],
      versionId: string,
    ): Promise<void> {
      const tagged = records.map((r) => ({ ...r, versionId }));
      await db.transaction(async (tx) => {
        for (let i = 0; i < tagged.length; i += BULK_CHUNK_SIZE) {
          const chunk = tagged.slice(i, i + BULK_CHUNK_SIZE);
          await tx.insert(governingRules).values(chunk);
        }
      });
    },

    /**
     * Batch insert functional centres. Set version_id on all records.
     */
    async bulkInsertFunctionalCentres(
      records: InsertFunctionalCentre[],
      versionId: string,
    ): Promise<void> {
      const tagged = records.map((r) => ({ ...r, versionId }));
      await db.transaction(async (tx) => {
        for (let i = 0; i < tagged.length; i += BULK_CHUNK_SIZE) {
          const chunk = tagged.slice(i, i + BULK_CHUNK_SIZE);
          await tx.insert(functionalCentres).values(chunk);
        }
      });
    },

    /**
     * Batch insert DI codes. Set version_id on all records.
     * Must handle ~14,000 records efficiently (chunked inserts of 1,000).
     */
    async bulkInsertDiCodes(
      records: InsertDiCode[],
      versionId: string,
    ): Promise<void> {
      const tagged = records.map((r) => ({ ...r, versionId }));
      await db.transaction(async (tx) => {
        for (let i = 0; i < tagged.length; i += BULK_CHUNK_SIZE) {
          const chunk = tagged.slice(i, i + BULK_CHUNK_SIZE);
          await tx.insert(diCodes).values(chunk);
        }
      });
    },

    /**
     * Batch insert RRNP communities. Set version_id on all records.
     */
    async bulkInsertRrnpCommunities(
      records: InsertRrnpCommunity[],
      versionId: string,
    ): Promise<void> {
      const tagged = records.map((r) => ({ ...r, versionId }));
      await db.transaction(async (tx) => {
        for (let i = 0; i < tagged.length; i += BULK_CHUNK_SIZE) {
          const chunk = tagged.slice(i, i + BULK_CHUNK_SIZE);
          await tx.insert(rrnpCommunities).values(chunk);
        }
      });
    },

    /**
     * Batch insert PCPCM baskets. Set version_id on all records.
     */
    async bulkInsertPcpcmBaskets(
      records: InsertPcpcmBasket[],
      versionId: string,
    ): Promise<void> {
      const tagged = records.map((r) => ({ ...r, versionId }));
      await db.transaction(async (tx) => {
        for (let i = 0; i < tagged.length; i += BULK_CHUNK_SIZE) {
          const chunk = tagged.slice(i, i + BULK_CHUNK_SIZE);
          await tx.insert(pcpcmBaskets).values(chunk);
        }
      });
    },

    /**
     * Batch insert explanatory codes. Set version_id on all records.
     */
    async bulkInsertExplanatoryCodes(
      records: InsertExplanatoryCode[],
      versionId: string,
    ): Promise<void> {
      const tagged = records.map((r) => ({ ...r, versionId }));
      await db.transaction(async (tx) => {
        for (let i = 0; i < tagged.length; i += BULK_CHUNK_SIZE) {
          const chunk = tagged.slice(i, i + BULK_CHUNK_SIZE);
          await tx.insert(explanatoryCodes).values(chunk);
        }
      });
    },
  };
}

/** Chunk size for bulk inserts to avoid exceeding PostgreSQL parameter limits. */
const BULK_CHUNK_SIZE = 1000;

export type ReferenceRepository = ReturnType<typeof createReferenceRepository>;
