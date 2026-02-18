import { eq, and, ne, count, lte, gte } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  providers,
  businessArrangements,
  practiceLocations,
  pcpcmEnrolments,
  wcbConfigurations,
  delegateRelationships,
  type InsertProvider,
  type SelectProvider,
  type InsertBa,
  type SelectBa,
  type InsertLocation,
  type SelectLocation,
  type InsertPcpcmEnrolment,
  type SelectPcpcmEnrolment,
  type InsertWcbConfig,
  type SelectWcbConfig,
  type InsertDelegateRelationship,
  type SelectDelegateRelationship,
  submissionPreferences,
  type InsertSubmissionPreferences,
  type SelectSubmissionPreferences,
  hlinkConfigurations,
  type InsertHlinkConfig,
  type SelectHlinkConfig,
} from '@meritum/shared/schemas/db/provider.schema.js';
import { users } from '@meritum/shared/schemas/db/iam.schema.js';
import {
  hscCodes,
  referenceDataVersions,
} from '@meritum/shared/schemas/db/reference.schema.js';
import type { ProviderContext } from '@meritum/shared/schemas/provider.schema.js';

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

function validatePermittedFormTypes(value: unknown): asserts value is string[] {
  if (!Array.isArray(value)) {
    throw new InvalidPermittedFormTypesError('permitted_form_types must be an array');
  }
  for (const item of value) {
    if (typeof item !== 'string') {
      throw new InvalidPermittedFormTypesError(
        'permitted_form_types must contain only strings',
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Required fields for onboarding completion
// ---------------------------------------------------------------------------

const ONBOARDING_REQUIRED_FIELDS: (keyof SelectProvider)[] = [
  'billingNumber',
  'cpsaRegistrationNumber',
  'firstName',
  'lastName',
  'specialtyCode',
  'physicianType',
];

// ---------------------------------------------------------------------------
// Provider Repository
// ---------------------------------------------------------------------------

export function createProviderRepository(db: NodePgDatabase) {
  return {
    /**
     * Insert a new provider record. provider_id must match the user_id
     * from Domain 1 (1:1 relationship).
     */
    async createProvider(data: InsertProvider): Promise<SelectProvider> {
      const rows = await db
        .insert(providers)
        .values(data)
        .returning();
      return rows[0];
    },

    /**
     * Find a provider by ID. Returns undefined if not found.
     */
    async findProviderById(
      providerId: string,
    ): Promise<SelectProvider | undefined> {
      const rows = await db
        .select()
        .from(providers)
        .where(eq(providers.providerId, providerId))
        .limit(1);
      return rows[0];
    },

    /**
     * Find a provider by billing number. Used for uniqueness validation.
     */
    async findProviderByBillingNumber(
      billingNumber: string,
    ): Promise<SelectProvider | undefined> {
      const rows = await db
        .select()
        .from(providers)
        .where(eq(providers.billingNumber, billingNumber))
        .limit(1);
      return rows[0];
    },

    /**
     * Find a provider by CPSA registration number.
     */
    async findProviderByCpsaNumber(
      cpsaNumber: string,
    ): Promise<SelectProvider | undefined> {
      const rows = await db
        .select()
        .from(providers)
        .where(eq(providers.cpsaRegistrationNumber, cpsaNumber))
        .limit(1);
      return rows[0];
    },

    /**
     * Update provider fields. Sets updated_at to now().
     */
    async updateProvider(
      providerId: string,
      data: Partial<InsertProvider>,
    ): Promise<SelectProvider | undefined> {
      const rows = await db
        .update(providers)
        .set({ ...data, updatedAt: new Date() })
        .where(eq(providers.providerId, providerId))
        .returning();
      return rows[0];
    },

    /**
     * Set onboarding_completed = true. Returns undefined if provider not
     * found. Throws if required fields are missing.
     */
    async completeOnboarding(
      providerId: string,
    ): Promise<SelectProvider | undefined> {
      // First, fetch the provider to validate required fields
      const existing = await db
        .select()
        .from(providers)
        .where(eq(providers.providerId, providerId))
        .limit(1);

      if (!existing[0]) return undefined;

      const provider = existing[0];
      const missing = ONBOARDING_REQUIRED_FIELDS.filter(
        (field) => !provider[field],
      );

      if (missing.length > 0) {
        throw new OnboardingIncompleteError(missing);
      }

      const rows = await db
        .update(providers)
        .set({ onboardingCompleted: true, updatedAt: new Date() })
        .where(eq(providers.providerId, providerId))
        .returning();
      return rows[0];
    },

    /**
     * Return which required fields are populated and which are missing.
     */
    async getOnboardingStatus(
      providerId: string,
    ): Promise<OnboardingStatus | undefined> {
      const rows = await db
        .select()
        .from(providers)
        .where(eq(providers.providerId, providerId))
        .limit(1);

      if (!rows[0]) return undefined;

      const provider = rows[0];
      const populated: string[] = [];
      const missing: string[] = [];

      for (const field of ONBOARDING_REQUIRED_FIELDS) {
        if (provider[field]) {
          populated.push(field);
        } else {
          missing.push(field);
        }
      }

      return {
        onboardingCompleted: provider.onboardingCompleted,
        populated,
        missing,
        complete: missing.length === 0,
      };
    },

    // -----------------------------------------------------------------
    // Business Arrangement (BA) Management
    // -----------------------------------------------------------------

    /**
     * Insert a new business arrangement.
     */
    async createBa(data: InsertBa): Promise<SelectBa> {
      const rows = await db
        .insert(businessArrangements)
        .values(data)
        .returning();
      return rows[0];
    },

    /**
     * Find a BA by ID, scoped to provider.
     */
    async findBaById(
      baId: string,
      providerId: string,
    ): Promise<SelectBa | undefined> {
      const rows = await db
        .select()
        .from(businessArrangements)
        .where(
          and(
            eq(businessArrangements.baId, baId),
            eq(businessArrangements.providerId, providerId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * List all BAs for a provider (all statuses).
     */
    async listBasForProvider(providerId: string): Promise<SelectBa[]> {
      return db
        .select()
        .from(businessArrangements)
        .where(eq(businessArrangements.providerId, providerId));
    },

    /**
     * List only active BAs for a provider.
     */
    async listActiveBasForProvider(providerId: string): Promise<SelectBa[]> {
      return db
        .select()
        .from(businessArrangements)
        .where(
          and(
            eq(businessArrangements.providerId, providerId),
            eq(businessArrangements.status, 'ACTIVE'),
          ),
        );
    },

    /**
     * Count active BAs for a provider (for max 2 enforcement).
     */
    async countActiveBasForProvider(providerId: string): Promise<number> {
      const rows = await db
        .select({ value: count() })
        .from(businessArrangements)
        .where(
          and(
            eq(businessArrangements.providerId, providerId),
            eq(businessArrangements.status, 'ACTIVE'),
          ),
        );
      return rows[0]?.value ?? 0;
    },

    /**
     * Update BA fields, scoped to provider. Returns undefined if not found
     * or not owned by provider.
     */
    async updateBa(
      baId: string,
      providerId: string,
      data: Partial<InsertBa>,
    ): Promise<SelectBa | undefined> {
      const rows = await db
        .update(businessArrangements)
        .set({ ...data, updatedAt: new Date() })
        .where(
          and(
            eq(businessArrangements.baId, baId),
            eq(businessArrangements.providerId, providerId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Deactivate a BA: set status = INACTIVE and end_date = today.
     * Scoped to provider. Returns undefined if not found.
     */
    async deactivateBa(
      baId: string,
      providerId: string,
    ): Promise<SelectBa | undefined> {
      const today = new Date().toISOString().split('T')[0];
      const rows = await db
        .update(businessArrangements)
        .set({
          status: 'INACTIVE',
          endDate: today,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(businessArrangements.baId, baId),
            eq(businessArrangements.providerId, providerId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Find an active BA by ba_number (system-wide uniqueness check).
     */
    async findBaByNumber(
      baNumber: string,
    ): Promise<SelectBa | undefined> {
      const rows = await db
        .select()
        .from(businessArrangements)
        .where(
          and(
            eq(businessArrangements.baNumber, baNumber),
            ne(businessArrangements.status, 'INACTIVE'),
          ),
        )
        .limit(1);
      return rows[0];
    },

    // -----------------------------------------------------------------
    // Practice Location Management
    // -----------------------------------------------------------------

    /**
     * Insert a new practice location.
     */
    async createLocation(data: InsertLocation): Promise<SelectLocation> {
      const rows = await db
        .insert(practiceLocations)
        .values(data)
        .returning();
      return rows[0];
    },

    /**
     * Find a location by ID, scoped to provider.
     */
    async findLocationById(
      locationId: string,
      providerId: string,
    ): Promise<SelectLocation | undefined> {
      const rows = await db
        .select()
        .from(practiceLocations)
        .where(
          and(
            eq(practiceLocations.locationId, locationId),
            eq(practiceLocations.providerId, providerId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * List all locations for a provider (all statuses).
     */
    async listLocationsForProvider(
      providerId: string,
    ): Promise<SelectLocation[]> {
      return db
        .select()
        .from(practiceLocations)
        .where(eq(practiceLocations.providerId, providerId));
    },

    /**
     * List only active locations for a provider (for claim creation dropdown).
     */
    async listActiveLocationsForProvider(
      providerId: string,
    ): Promise<SelectLocation[]> {
      return db
        .select()
        .from(practiceLocations)
        .where(
          and(
            eq(practiceLocations.providerId, providerId),
            eq(practiceLocations.isActive, true),
          ),
        );
    },

    /**
     * Update location fields, scoped to provider.
     */
    async updateLocation(
      locationId: string,
      providerId: string,
      data: Partial<InsertLocation>,
    ): Promise<SelectLocation | undefined> {
      const rows = await db
        .update(practiceLocations)
        .set({ ...data, updatedAt: new Date() })
        .where(
          and(
            eq(practiceLocations.locationId, locationId),
            eq(practiceLocations.providerId, providerId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Set a location as the default for the provider.
     * Uses a transaction to unset the current default first,
     * ensuring exactly one default at all times.
     */
    async setDefaultLocation(
      locationId: string,
      providerId: string,
    ): Promise<SelectLocation | undefined> {
      return db.transaction(async (tx: NodePgDatabase) => {
        // Unset current default(s) for this provider
        await tx
          .update(practiceLocations)
          .set({ isDefault: false, updatedAt: new Date() })
          .where(
            and(
              eq(practiceLocations.providerId, providerId),
              eq(practiceLocations.isDefault, true),
            ),
          );

        // Set the new default
        const rows = await tx
          .update(practiceLocations)
          .set({ isDefault: true, updatedAt: new Date() })
          .where(
            and(
              eq(practiceLocations.locationId, locationId),
              eq(practiceLocations.providerId, providerId),
            ),
          )
          .returning();
        return rows[0];
      });
    },

    /**
     * Deactivate a location. If it was the default, clear is_default.
     */
    async deactivateLocation(
      locationId: string,
      providerId: string,
    ): Promise<SelectLocation | undefined> {
      const rows = await db
        .update(practiceLocations)
        .set({ isActive: false, isDefault: false, updatedAt: new Date() })
        .where(
          and(
            eq(practiceLocations.locationId, locationId),
            eq(practiceLocations.providerId, providerId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Return the default location for a provider, or undefined if none set.
     */
    async getDefaultLocation(
      providerId: string,
    ): Promise<SelectLocation | undefined> {
      const rows = await db
        .select()
        .from(practiceLocations)
        .where(
          and(
            eq(practiceLocations.providerId, providerId),
            eq(practiceLocations.isDefault, true),
            eq(practiceLocations.isActive, true),
          ),
        )
        .limit(1);
      return rows[0];
    },

    // -----------------------------------------------------------------
    // PCPCM Enrolment Management
    // -----------------------------------------------------------------

    /**
     * Insert a PCPCM enrolment linking PCPCM and FFS BAs.
     */
    async createPcpcmEnrolment(
      data: InsertPcpcmEnrolment,
    ): Promise<SelectPcpcmEnrolment> {
      const rows = await db
        .insert(pcpcmEnrolments)
        .values(data)
        .returning();
      return rows[0];
    },

    /**
     * Find the active (non-WITHDRAWN) PCPCM enrolment for a provider.
     */
    async findPcpcmEnrolmentForProvider(
      providerId: string,
    ): Promise<SelectPcpcmEnrolment | undefined> {
      const rows = await db
        .select()
        .from(pcpcmEnrolments)
        .where(
          and(
            eq(pcpcmEnrolments.providerId, providerId),
            ne(pcpcmEnrolments.status, 'WITHDRAWN'),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * Update a PCPCM enrolment (e.g. panel size or status), scoped to provider.
     */
    async updatePcpcmEnrolment(
      enrolmentId: string,
      providerId: string,
      data: Partial<InsertPcpcmEnrolment>,
    ): Promise<SelectPcpcmEnrolment | undefined> {
      const rows = await db
        .update(pcpcmEnrolments)
        .set({ ...data, updatedAt: new Date() })
        .where(
          and(
            eq(pcpcmEnrolments.enrolmentId, enrolmentId),
            eq(pcpcmEnrolments.providerId, providerId),
          ),
        )
        .returning();
      return rows[0];
    },

    // -----------------------------------------------------------------
    // WCB Configuration Management
    // -----------------------------------------------------------------

    /**
     * Insert a WCB configuration. Validates permittedFormTypes is a string array.
     */
    async createWcbConfig(
      data: InsertWcbConfig,
    ): Promise<SelectWcbConfig> {
      validatePermittedFormTypes(data.permittedFormTypes);
      const rows = await db
        .insert(wcbConfigurations)
        .values(data)
        .returning();
      return rows[0];
    },

    /**
     * Find a WCB config by ID, scoped to provider.
     */
    async findWcbConfigById(
      wcbConfigId: string,
      providerId: string,
    ): Promise<SelectWcbConfig | undefined> {
      const rows = await db
        .select()
        .from(wcbConfigurations)
        .where(
          and(
            eq(wcbConfigurations.wcbConfigId, wcbConfigId),
            eq(wcbConfigurations.providerId, providerId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * List all WCB configurations for a provider.
     */
    async listWcbConfigsForProvider(
      providerId: string,
    ): Promise<SelectWcbConfig[]> {
      return db
        .select()
        .from(wcbConfigurations)
        .where(eq(wcbConfigurations.providerId, providerId));
    },

    /**
     * Update WCB config fields, scoped to provider. Validates permittedFormTypes
     * if included.
     */
    async updateWcbConfig(
      wcbConfigId: string,
      providerId: string,
      data: Partial<InsertWcbConfig>,
    ): Promise<SelectWcbConfig | undefined> {
      if (data.permittedFormTypes !== undefined) {
        validatePermittedFormTypes(data.permittedFormTypes);
      }
      const rows = await db
        .update(wcbConfigurations)
        .set({ ...data, updatedAt: new Date() })
        .where(
          and(
            eq(wcbConfigurations.wcbConfigId, wcbConfigId),
            eq(wcbConfigurations.providerId, providerId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Hard delete a WCB config, scoped to provider.
     * Returns true if a row was deleted, false otherwise.
     */
    async deleteWcbConfig(
      wcbConfigId: string,
      providerId: string,
    ): Promise<boolean> {
      const rows = await db
        .delete(wcbConfigurations)
        .where(
          and(
            eq(wcbConfigurations.wcbConfigId, wcbConfigId),
            eq(wcbConfigurations.providerId, providerId),
          ),
        )
        .returning();
      return rows.length > 0;
    },

    /**
     * Set a WCB config as the default for the provider.
     * Uses a transaction to unset the current default first.
     */
    async setDefaultWcbConfig(
      wcbConfigId: string,
      providerId: string,
    ): Promise<SelectWcbConfig | undefined> {
      return db.transaction(async (tx: NodePgDatabase) => {
        // Unset current default(s) for this provider
        await tx
          .update(wcbConfigurations)
          .set({ isDefault: false, updatedAt: new Date() })
          .where(
            and(
              eq(wcbConfigurations.providerId, providerId),
              eq(wcbConfigurations.isDefault, true),
            ),
          );

        // Set the new default
        const rows = await tx
          .update(wcbConfigurations)
          .set({ isDefault: true, updatedAt: new Date() })
          .where(
            and(
              eq(wcbConfigurations.wcbConfigId, wcbConfigId),
              eq(wcbConfigurations.providerId, providerId),
            ),
          )
          .returning();
        return rows[0];
      });
    },

    /**
     * Aggregate all permitted_form_types across all WCB configs for a provider.
     * Returns a deduplicated array of form type strings.
     */
    async getAggregatedFormPermissions(
      providerId: string,
    ): Promise<string[]> {
      const configs = await db
        .select()
        .from(wcbConfigurations)
        .where(eq(wcbConfigurations.providerId, providerId));

      const allTypes = new Set<string>();
      for (const config of configs) {
        const types = config.permittedFormTypes;
        if (Array.isArray(types)) {
          for (const t of types) {
            if (typeof t === 'string') {
              allTypes.add(t);
            }
          }
        }
      }
      return [...allTypes];
    },

    // -----------------------------------------------------------------
    // Delegate Relationship Management
    // -----------------------------------------------------------------

    /**
     * Insert a new delegate relationship with status INVITED.
     */
    async createDelegateRelationship(
      data: InsertDelegateRelationship,
    ): Promise<SelectDelegateRelationship> {
      const rows = await db
        .insert(delegateRelationships)
        .values({ ...data, status: 'INVITED' })
        .returning();
      return rows[0];
    },

    /**
     * Find a delegate relationship by ID, scoped to physician.
     */
    async findRelationshipById(
      relationshipId: string,
      physicianId: string,
    ): Promise<SelectDelegateRelationship | undefined> {
      const rows = await db
        .select()
        .from(delegateRelationships)
        .where(
          and(
            eq(delegateRelationships.relationshipId, relationshipId),
            eq(delegateRelationships.physicianId, physicianId),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * Find the active (non-REVOKED) relationship between a physician and delegate user.
     */
    async findActiveRelationship(
      physicianId: string,
      delegateUserId: string,
    ): Promise<SelectDelegateRelationship | undefined> {
      const rows = await db
        .select()
        .from(delegateRelationships)
        .where(
          and(
            eq(delegateRelationships.physicianId, physicianId),
            eq(delegateRelationships.delegateUserId, delegateUserId),
            ne(delegateRelationships.status, 'REVOKED'),
          ),
        )
        .limit(1);
      return rows[0];
    },

    /**
     * List all delegate relationships for a physician (ACTIVE, INVITED, REVOKED)
     * with delegate user info joined from Domain 1 users table.
     */
    async listDelegatesForPhysician(
      physicianId: string,
    ): Promise<DelegateWithUserInfo[]> {
      const rows = await db
        .select({
          relationshipId: delegateRelationships.relationshipId,
          physicianId: delegateRelationships.physicianId,
          delegateUserId: delegateRelationships.delegateUserId,
          permissions: delegateRelationships.permissions,
          status: delegateRelationships.status,
          invitedAt: delegateRelationships.invitedAt,
          acceptedAt: delegateRelationships.acceptedAt,
          revokedAt: delegateRelationships.revokedAt,
          revokedBy: delegateRelationships.revokedBy,
          createdAt: delegateRelationships.createdAt,
          updatedAt: delegateRelationships.updatedAt,
          delegateEmail: users.email,
          delegateFullName: users.fullName,
        })
        .from(delegateRelationships)
        .where(eq(delegateRelationships.physicianId, physicianId));
      return rows;
    },

    /**
     * List all physicians the delegate serves (ACTIVE only)
     * with permissions per physician.
     */
    async listPhysiciansForDelegate(
      delegateUserId: string,
    ): Promise<PhysicianForDelegate[]> {
      const rows = await db
        .select({
          relationshipId: delegateRelationships.relationshipId,
          physicianId: delegateRelationships.physicianId,
          delegateUserId: delegateRelationships.delegateUserId,
          permissions: delegateRelationships.permissions,
          status: delegateRelationships.status,
          invitedAt: delegateRelationships.invitedAt,
          acceptedAt: delegateRelationships.acceptedAt,
          createdAt: delegateRelationships.createdAt,
          updatedAt: delegateRelationships.updatedAt,
          physicianFirstName: providers.firstName,
          physicianLastName: providers.lastName,
        })
        .from(delegateRelationships)
        .where(
          and(
            eq(delegateRelationships.delegateUserId, delegateUserId),
            eq(delegateRelationships.status, 'ACTIVE'),
          ),
        );
      return rows;
    },

    /**
     * Update delegate permissions JSONB, scoped to physician.
     * Returns undefined if relationship not found or not owned by physician.
     */
    async updateDelegatePermissions(
      relationshipId: string,
      physicianId: string,
      permissions: string[],
    ): Promise<SelectDelegateRelationship | undefined> {
      const rows = await db
        .update(delegateRelationships)
        .set({ permissions, updatedAt: new Date() })
        .where(
          and(
            eq(delegateRelationships.relationshipId, relationshipId),
            eq(delegateRelationships.physicianId, physicianId),
          ),
        )
        .returning();
      return rows[0];
    },

    /**
     * Accept a delegate relationship: set status = ACTIVE, accepted_at = now().
     */
    async acceptRelationship(
      relationshipId: string,
    ): Promise<SelectDelegateRelationship | undefined> {
      const rows = await db
        .update(delegateRelationships)
        .set({
          status: 'ACTIVE',
          acceptedAt: new Date(),
          updatedAt: new Date(),
        })
        .where(eq(delegateRelationships.relationshipId, relationshipId))
        .returning();
      return rows[0];
    },

    /**
     * Revoke a delegate relationship: set status = REVOKED, revoked_at = now(),
     * revoked_by = revokedBy.
     * Scoped to physician.
     */
    async revokeRelationship(
      relationshipId: string,
      physicianId: string,
      revokedBy: string,
    ): Promise<SelectDelegateRelationship | undefined> {
      const rows = await db
        .update(delegateRelationships)
        .set({
          status: 'REVOKED',
          revokedAt: new Date(),
          revokedBy,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(delegateRelationships.relationshipId, relationshipId),
            eq(delegateRelationships.physicianId, physicianId),
          ),
        )
        .returning();
      return rows[0];
    },

    // -----------------------------------------------------------------
    // Submission Preferences Management
    // -----------------------------------------------------------------

    /**
     * Insert default submission preferences during onboarding.
     * One row per physician (provider_id is unique).
     */
    async createSubmissionPreferences(
      data: InsertSubmissionPreferences,
    ): Promise<SelectSubmissionPreferences> {
      const rows = await db
        .insert(submissionPreferences)
        .values(data)
        .returning();
      return rows[0];
    },

    /**
     * Find submission preferences for a provider.
     * Scoped to providerId.
     */
    async findSubmissionPreferences(
      providerId: string,
    ): Promise<SelectSubmissionPreferences | undefined> {
      const rows = await db
        .select()
        .from(submissionPreferences)
        .where(eq(submissionPreferences.providerId, providerId))
        .limit(1);
      return rows[0];
    },

    /**
     * Update submission preferences. Sets updated_by to the actor.
     * Scoped to providerId.
     */
    async updateSubmissionPreferences(
      providerId: string,
      data: Partial<InsertSubmissionPreferences>,
      updatedBy: string,
    ): Promise<SelectSubmissionPreferences | undefined> {
      const rows = await db
        .update(submissionPreferences)
        .set({ ...data, updatedBy, updatedAt: new Date() })
        .where(eq(submissionPreferences.providerId, providerId))
        .returning();
      return rows[0];
    },

    // -----------------------------------------------------------------
    // H-Link Configuration Management
    // -----------------------------------------------------------------

    /**
     * Insert H-Link configuration for a provider.
     * One row per physician (provider_id is unique).
     * credential_secret_ref is a reference to secrets management —
     * actual credentials are NEVER stored in the database.
     */
    async createHlinkConfig(
      data: InsertHlinkConfig,
    ): Promise<SelectHlinkConfig> {
      const rows = await db
        .insert(hlinkConfigurations)
        .values(data)
        .returning();
      return rows[0];
    },

    /**
     * Find H-Link config for a provider.
     * Scoped to providerId.
     */
    async findHlinkConfig(
      providerId: string,
    ): Promise<SelectHlinkConfig | undefined> {
      const rows = await db
        .select()
        .from(hlinkConfigurations)
        .where(eq(hlinkConfigurations.providerId, providerId))
        .limit(1);
      return rows[0];
    },

    /**
     * Update H-Link config fields.
     * Scoped to providerId.
     */
    async updateHlinkConfig(
      providerId: string,
      data: Partial<InsertHlinkConfig>,
    ): Promise<SelectHlinkConfig | undefined> {
      const rows = await db
        .update(hlinkConfigurations)
        .set({ ...data, updatedAt: new Date() })
        .where(eq(hlinkConfigurations.providerId, providerId))
        .returning();
      return rows[0];
    },

    /**
     * Update the last_successful_transmission timestamp.
     * Scoped to providerId.
     */
    async updateLastTransmission(
      providerId: string,
      timestamp: Date,
    ): Promise<SelectHlinkConfig | undefined> {
      const rows = await db
        .update(hlinkConfigurations)
        .set({ lastSuccessfulTransmission: timestamp, updatedAt: new Date() })
        .where(eq(hlinkConfigurations.providerId, providerId))
        .returning();
      return rows[0];
    },

    // -----------------------------------------------------------------
    // Provider Context Queries (Internal API for Domain 4)
    // -----------------------------------------------------------------

    /**
     * Assemble the complete ProviderContext object for a provider.
     * Returns null if the provider does not exist.
     * All queries are scoped to the given providerId.
     */
    async getFullProviderContext(
      providerId: string,
    ): Promise<ProviderContext | null> {
      // Fetch provider record
      const providerRows = await db
        .select()
        .from(providers)
        .where(eq(providers.providerId, providerId))
        .limit(1);

      const provider = providerRows[0];
      if (!provider) return null;

      // Fetch all active BAs
      const activeBas = await db
        .select()
        .from(businessArrangements)
        .where(
          and(
            eq(businessArrangements.providerId, providerId),
            eq(businessArrangements.status, 'ACTIVE'),
          ),
        );

      // Fetch all active locations
      const activeLocations = await db
        .select()
        .from(practiceLocations)
        .where(
          and(
            eq(practiceLocations.providerId, providerId),
            eq(practiceLocations.isActive, true),
          ),
        );

      // Find default location
      const defaultLocation = activeLocations.find((l) => l.isDefault) ?? null;

      // Fetch PCPCM enrolment (non-WITHDRAWN)
      const pcpcmRows = await db
        .select()
        .from(pcpcmEnrolments)
        .where(
          and(
            eq(pcpcmEnrolments.providerId, providerId),
            ne(pcpcmEnrolments.status, 'WITHDRAWN'),
          ),
        )
        .limit(1);

      const pcpcmEnrolment = pcpcmRows[0] ?? null;
      const pcpcmEnrolled = pcpcmEnrolment?.status === 'ACTIVE';

      // Resolve PCPCM and FFS BA numbers from enrolment
      let pcpcmBaNumber: string | null = null;
      let ffsBaNumber: string | null = null;
      if (pcpcmEnrolment) {
        const pcpcmBa = activeBas.find(
          (ba) => ba.baId === pcpcmEnrolment.pcpcmBaId,
        );
        const ffsBa = activeBas.find(
          (ba) => ba.baId === pcpcmEnrolment.ffsBaId,
        );
        pcpcmBaNumber = pcpcmBa?.baNumber ?? null;
        ffsBaNumber = ffsBa?.baNumber ?? null;
      }

      // Fetch WCB configurations
      const wcbConfigs = await db
        .select()
        .from(wcbConfigurations)
        .where(eq(wcbConfigurations.providerId, providerId));

      const defaultWcbConfig = wcbConfigs.find((c) => c.isDefault) ?? null;

      // Fetch submission preferences
      const prefRows = await db
        .select()
        .from(submissionPreferences)
        .where(eq(submissionPreferences.providerId, providerId))
        .limit(1);

      const prefs = prefRows[0] ?? null;

      // Fetch H-Link configuration
      const hlinkRows = await db
        .select()
        .from(hlinkConfigurations)
        .where(eq(hlinkConfigurations.providerId, providerId))
        .limit(1);

      const hlink = hlinkRows[0] ?? null;

      return {
        provider_id: provider.providerId,
        billing_number: provider.billingNumber,
        specialty_code: provider.specialtyCode ?? '',
        physician_type: provider.physicianType ?? '',
        bas: activeBas.map((ba) => ({
          ba_id: ba.baId,
          ba_number: ba.baNumber,
          ba_type: ba.baType,
          is_primary: ba.isPrimary,
          status: ba.status,
        })),
        default_location: defaultLocation
          ? {
              location_id: defaultLocation.locationId,
              name: defaultLocation.name,
              functional_centre: defaultLocation.functionalCentre,
              facility_number: defaultLocation.facilityNumber,
            }
          : null,
        all_locations: activeLocations.map((l) => ({
          location_id: l.locationId,
          name: l.name,
          functional_centre: l.functionalCentre,
          is_active: l.isActive,
        })),
        pcpcm_enrolled: pcpcmEnrolled,
        pcpcm_ba_number: pcpcmBaNumber,
        ffs_ba_number: ffsBaNumber,
        wcb_configs: wcbConfigs.map((c) => ({
          wcb_config_id: c.wcbConfigId,
          contract_id: c.contractId,
          role_code: c.roleCode,
          permitted_form_types: Array.isArray(c.permittedFormTypes)
            ? (c.permittedFormTypes as string[])
            : [],
        })),
        default_wcb_config: defaultWcbConfig
          ? {
              wcb_config_id: defaultWcbConfig.wcbConfigId,
              contract_id: defaultWcbConfig.contractId,
              role_code: defaultWcbConfig.roleCode,
            }
          : null,
        submission_preferences: prefs
          ? {
              ahcip_submission_mode: prefs.ahcipSubmissionMode,
              wcb_submission_mode: prefs.wcbSubmissionMode,
              batch_review_reminder: prefs.batchReviewReminder,
              deadline_reminder_days: prefs.deadlineReminderDays,
            }
          : null,
        hlink_accreditation_status: hlink?.accreditationStatus ?? null,
        hlink_submitter_prefix: hlink?.submitterPrefix ?? null,
        onboarding_completed: provider.onboardingCompleted,
        status: provider.status ?? 'ACTIVE',
      };
    },

    /**
     * Return the correct BA number for a claim.
     *
     * For AHCIP:
     *   - If the physician is PCPCM-enrolled and an hscCode is provided,
     *     look up the HSC code's pcpcmBasket field using the SOMB version
     *     effective at the date of service (or current active version).
     *   - If the basket is not 'not_applicable', return the PCPCM BA number.
     *   - Otherwise, return the FFS BA number (paired in PCPCM enrolment)
     *     or the primary BA if not PCPCM-enrolled.
     *
     * For WCB:
     *   - Return the primary BA number.
     *
     * Returns null if no suitable BA is found.
     */
    async getBaForClaim(
      providerId: string,
      claimType: 'AHCIP' | 'WCB',
      hscCode?: string,
      dateOfService?: string,
    ): Promise<{ baNumber: string; baType: string; routing: 'PCPCM' | 'FFS' | 'PRIMARY' } | null> {
      // Fetch active BAs for this provider
      const activeBas = await db
        .select()
        .from(businessArrangements)
        .where(
          and(
            eq(businessArrangements.providerId, providerId),
            eq(businessArrangements.status, 'ACTIVE'),
          ),
        );

      if (activeBas.length === 0) return null;

      if (claimType === 'WCB') {
        const primaryBa = activeBas.find((ba) => ba.isPrimary);
        const fallback = primaryBa ?? activeBas[0];
        return {
          baNumber: fallback.baNumber,
          baType: fallback.baType,
          routing: 'PRIMARY',
        };
      }

      // AHCIP path
      // Check for PCPCM enrolment
      const pcpcmRows = await db
        .select()
        .from(pcpcmEnrolments)
        .where(
          and(
            eq(pcpcmEnrolments.providerId, providerId),
            eq(pcpcmEnrolments.status, 'ACTIVE'),
          ),
        )
        .limit(1);

      const pcpcmEnrolment = pcpcmRows[0];

      if (!pcpcmEnrolment || !hscCode) {
        // Not PCPCM-enrolled or no HSC code — return primary/FFS BA
        const primaryBa = activeBas.find((ba) => ba.isPrimary);
        const fallback = primaryBa ?? activeBas[0];
        return {
          baNumber: fallback.baNumber,
          baType: fallback.baType,
          routing: 'PRIMARY',
        };
      }

      // PCPCM-enrolled with HSC code — look up basket classification
      // Use SOMB version effective at date of service
      let basket: string | null = null;

      if (dateOfService) {
        // Find SOMB version effective at the date of service
        const versionRows = await db
          .select()
          .from(referenceDataVersions)
          .where(
            and(
              eq(referenceDataVersions.dataSet, 'somb'),
              eq(referenceDataVersions.isActive, true),
              lte(referenceDataVersions.effectiveFrom, dateOfService),
            ),
          )
          .limit(1);

        const version = versionRows[0];
        if (version) {
          const hscRows = await db
            .select()
            .from(hscCodes)
            .where(
              and(
                eq(hscCodes.hscCode, hscCode),
                eq(hscCodes.versionId, version.versionId),
              ),
            )
            .limit(1);

          basket = hscRows[0]?.pcpcmBasket ?? null;
        }
      }

      if (!basket) {
        // Fallback: use current active SOMB version
        const versionRows = await db
          .select()
          .from(referenceDataVersions)
          .where(
            and(
              eq(referenceDataVersions.dataSet, 'somb'),
              eq(referenceDataVersions.isActive, true),
            ),
          )
          .limit(1);

        const version = versionRows[0];
        if (version) {
          const hscRows = await db
            .select()
            .from(hscCodes)
            .where(
              and(
                eq(hscCodes.hscCode, hscCode),
                eq(hscCodes.versionId, version.versionId),
              ),
            )
            .limit(1);

          basket = hscRows[0]?.pcpcmBasket ?? null;
        }
      }

      // Determine routing based on basket
      if (basket && basket !== 'not_applicable') {
        // In-basket: route to PCPCM BA
        const pcpcmBa = activeBas.find(
          (ba) => ba.baId === pcpcmEnrolment.pcpcmBaId,
        );
        if (pcpcmBa) {
          return {
            baNumber: pcpcmBa.baNumber,
            baType: pcpcmBa.baType,
            routing: 'PCPCM',
          };
        }
      }

      // Out-of-basket or no basket classification: route to FFS BA
      const ffsBa = activeBas.find(
        (ba) => ba.baId === pcpcmEnrolment.ffsBaId,
      );
      if (ffsBa) {
        return {
          baNumber: ffsBa.baNumber,
          baType: ffsBa.baType,
          routing: 'FFS',
        };
      }

      // Fallback to primary BA
      const primaryBa = activeBas.find((ba) => ba.isPrimary);
      const fallback = primaryBa ?? activeBas[0];
      return {
        baNumber: fallback.baNumber,
        baType: fallback.baType,
        routing: 'FFS',
      };
    },

    /**
     * Find the WCB configuration whose permitted_form_types includes the given formId.
     * Returns the contract_id, role_code, and wcb_config_id, or null if not permitted.
     * Scoped to providerId.
     */
    async getWcbConfigForForm(
      providerId: string,
      formId: string,
    ): Promise<{ wcbConfigId: string; contractId: string; roleCode: string } | null> {
      const configs = await db
        .select()
        .from(wcbConfigurations)
        .where(eq(wcbConfigurations.providerId, providerId));

      for (const config of configs) {
        const types = config.permittedFormTypes;
        if (Array.isArray(types) && types.includes(formId)) {
          return {
            wcbConfigId: config.wcbConfigId,
            contractId: config.contractId,
            roleCode: config.roleCode,
          };
        }
      }

      return null;
    },
  };
}

export type ProviderRepository = ReturnType<typeof createProviderRepository>;

// ---------------------------------------------------------------------------
// Onboarding types
// ---------------------------------------------------------------------------

export interface OnboardingStatus {
  onboardingCompleted: boolean;
  populated: string[];
  missing: string[];
  complete: boolean;
}

export class OnboardingIncompleteError extends Error {
  public readonly missingFields: string[];

  constructor(missingFields: string[]) {
    super(
      `Cannot complete onboarding: missing required fields: ${missingFields.join(', ')}`,
    );
    this.name = 'OnboardingIncompleteError';
    this.missingFields = missingFields;
  }
}

export class InvalidPermittedFormTypesError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidPermittedFormTypesError';
  }
}

// ---------------------------------------------------------------------------
// Delegate relationship types
// ---------------------------------------------------------------------------

export interface DelegateWithUserInfo {
  relationshipId: string;
  physicianId: string;
  delegateUserId: string;
  permissions: unknown;
  status: string;
  invitedAt: Date;
  acceptedAt: Date | null;
  revokedAt: Date | null;
  revokedBy: string | null;
  createdAt: Date;
  updatedAt: Date;
  delegateEmail: string;
  delegateFullName: string;
}

export interface PhysicianForDelegate {
  relationshipId: string;
  physicianId: string;
  delegateUserId: string;
  permissions: unknown;
  status: string;
  invitedAt: Date;
  acceptedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
  physicianFirstName: string;
  physicianLastName: string;
}
