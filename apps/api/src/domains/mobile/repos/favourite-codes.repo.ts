import { eq, and, asc, count, inArray } from 'drizzle-orm';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import {
  favouriteCodes,
  type InsertFavouriteCode,
  type SelectFavouriteCode,
} from '@meritum/shared/schemas/db/mobile.schema.js';
import { MAX_FAVOURITES } from '@meritum/shared/constants/mobile.constants.js';
import { ConflictError, BusinessRuleError } from '../../../lib/errors.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ReorderItem {
  favourite_id: string;
  sort_order: number;
}

// ---------------------------------------------------------------------------
// Favourite Codes Repository
// ---------------------------------------------------------------------------

export function createFavouriteCodesRepository(db: NodePgDatabase) {
  return {
    /**
     * Create a new favourite code.
     * Enforces max 30 per provider (count check before insert).
     * Throws ConflictError on duplicate HSC for this provider.
     * Throws BusinessRuleError if max favourites reached.
     */
    async create(
      data: Pick<
        InsertFavouriteCode,
        'providerId' | 'healthServiceCode' | 'displayName' | 'sortOrder' | 'defaultModifiers'
      >,
    ): Promise<SelectFavouriteCode> {
      // Check count before insert
      const currentCount = await this.countByProvider(data.providerId);
      if (currentCount >= MAX_FAVOURITES) {
        throw new BusinessRuleError(
          `Maximum of ${MAX_FAVOURITES} favourite codes allowed per physician`,
        );
      }

      try {
        const rows = await db
          .insert(favouriteCodes)
          .values({
            providerId: data.providerId,
            healthServiceCode: data.healthServiceCode,
            displayName: data.displayName ?? null,
            sortOrder: data.sortOrder,
            defaultModifiers: data.defaultModifiers ?? null,
          })
          .returning();
        return rows[0];
      } catch (err: any) {
        if (err.code === '23505' && err.constraint?.includes('provider_hsc')) {
          throw new ConflictError(
            'This health service code is already in your favourites',
          );
        }
        throw err;
      }
    },

    /**
     * Fetch favourite by ID scoped to provider.
     * Returns null for wrong provider (404 pattern).
     */
    async getById(
      favouriteId: string,
      providerId: string,
    ): Promise<SelectFavouriteCode | null> {
      const rows = await db
        .select()
        .from(favouriteCodes)
        .where(
          and(
            eq(favouriteCodes.favouriteId, favouriteId),
            eq(favouriteCodes.providerId, providerId),
          ),
        )
        .limit(1);
      return rows[0] ?? null;
    },

    /**
     * Update display_name, default_modifiers, and/or sort_order.
     * Returns updated favourite, or null if not found / wrong provider.
     */
    async update(
      favouriteId: string,
      providerId: string,
      data: Partial<Pick<InsertFavouriteCode, 'displayName' | 'defaultModifiers' | 'sortOrder'>>,
    ): Promise<SelectFavouriteCode | null> {
      const rows = await db
        .update(favouriteCodes)
        .set(data)
        .where(
          and(
            eq(favouriteCodes.favouriteId, favouriteId),
            eq(favouriteCodes.providerId, providerId),
          ),
        )
        .returning();
      return rows[0] ?? null;
    },

    /**
     * Hard delete a favourite. Favourites are not PHI so hard delete is fine.
     * Returns true if deleted, false if not found / wrong provider.
     */
    async delete(
      favouriteId: string,
      providerId: string,
    ): Promise<boolean> {
      const rows = await db
        .delete(favouriteCodes)
        .where(
          and(
            eq(favouriteCodes.favouriteId, favouriteId),
            eq(favouriteCodes.providerId, providerId),
          ),
        )
        .returning();
      return rows.length > 0;
    },

    /**
     * List all favourites for a provider ordered by sort_order ASC.
     */
    async listByProvider(providerId: string): Promise<SelectFavouriteCode[]> {
      return db
        .select()
        .from(favouriteCodes)
        .where(eq(favouriteCodes.providerId, providerId))
        .orderBy(asc(favouriteCodes.sortOrder));
    },

    /**
     * Bulk update sort_order for multiple favourites in a single transaction.
     * Validates all favourite_ids belong to this provider before updating.
     * Throws BusinessRuleError if any favourite_id does not belong to the provider.
     */
    async reorder(
      providerId: string,
      items: ReorderItem[],
    ): Promise<void> {
      if (items.length === 0) return;

      const favouriteIds = items.map((i) => i.favourite_id);

      // Verify all favourite_ids belong to this provider
      const owned = await db
        .select({ favouriteId: favouriteCodes.favouriteId })
        .from(favouriteCodes)
        .where(
          and(
            eq(favouriteCodes.providerId, providerId),
            inArray(favouriteCodes.favouriteId, favouriteIds),
          ),
        );

      if (owned.length !== favouriteIds.length) {
        throw new BusinessRuleError(
          'One or more favourite IDs do not belong to this physician',
        );
      }

      // Update each item's sort_order
      await Promise.all(
        items.map((item) =>
          db
            .update(favouriteCodes)
            .set({ sortOrder: item.sort_order })
            .where(
              and(
                eq(favouriteCodes.favouriteId, item.favourite_id),
                eq(favouriteCodes.providerId, providerId),
              ),
            ),
        ),
      );
    },

    /**
     * Return count of favourites for a provider.
     * Used for max-30 enforcement.
     */
    async countByProvider(providerId: string): Promise<number> {
      const result = await db
        .select({ total: count() })
        .from(favouriteCodes)
        .where(eq(favouriteCodes.providerId, providerId));
      return Number(result[0]?.total ?? 0);
    },

    /**
     * Batch insert favourites for initial seeding.
     * Used when auto-seeding from claim history or specialty defaults.
     * Enforces max 30 total (existing + new).
     * Throws BusinessRuleError if total would exceed MAX_FAVOURITES.
     * Throws ConflictError on duplicate HSC for this provider.
     */
    async bulkCreate(
      providerId: string,
      items: Pick<
        InsertFavouriteCode,
        'healthServiceCode' | 'displayName' | 'sortOrder' | 'defaultModifiers'
      >[],
    ): Promise<SelectFavouriteCode[]> {
      if (items.length === 0) return [];

      // Check count before bulk insert
      const currentCount = await this.countByProvider(providerId);
      if (currentCount + items.length > MAX_FAVOURITES) {
        throw new BusinessRuleError(
          `Adding ${items.length} favourites would exceed the maximum of ${MAX_FAVOURITES}. Currently have ${currentCount}.`,
        );
      }

      try {
        const rows = await db
          .insert(favouriteCodes)
          .values(
            items.map((item) => ({
              providerId,
              healthServiceCode: item.healthServiceCode,
              displayName: item.displayName ?? null,
              sortOrder: item.sortOrder,
              defaultModifiers: item.defaultModifiers ?? null,
            })),
          )
          .returning();
        return rows;
      } catch (err: any) {
        if (err.code === '23505' && err.constraint?.includes('provider_hsc')) {
          throw new ConflictError(
            'One or more health service codes are already in your favourites',
          );
        }
        throw err;
      }
    },
  };
}

export type FavouriteCodesRepository = ReturnType<typeof createFavouriteCodesRepository>;
