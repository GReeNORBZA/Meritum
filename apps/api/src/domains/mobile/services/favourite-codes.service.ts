import type { FavouriteCodesRepository } from '../repos/favourite-codes.repo.js';
import type { SelectFavouriteCode } from '@meritum/shared/schemas/db/mobile.schema.js';
import {
  MAX_FAVOURITES,
  AUTO_SEED_COUNT,
  MobileAuditAction,
} from '@meritum/shared/constants/mobile.constants.js';
import {
  NotFoundError,
  BusinessRuleError,
  ValidationError,
} from '../../../lib/errors.js';

// ---------------------------------------------------------------------------
// Dependency interfaces (injected by handler / test)
// ---------------------------------------------------------------------------

export interface HscCodeLookup {
  findByCode(hscCode: string): Promise<{
    code: string;
    description: string;
    baseFee: string | null;
    feeType: string;
  } | null>;
}

export interface ModifierLookup {
  isKnownModifier(modifierCode: string): Promise<boolean>;
}

export interface ClaimHistoryQuery {
  getTopBilledCodes(
    providerId: string,
    limit: number,
  ): Promise<Array<{ healthServiceCode: string; count: number }>>;
}

export interface ProviderProfileQuery {
  getSpecialty(providerId: string): Promise<string | null>;
}

export interface SpecialtyDefaultsQuery {
  getDefaultCodes(specialty: string): Promise<string[]>;
}

export interface AuditRepo {
  appendAuditLog(entry: {
    userId?: string | null;
    action: string;
    category: string;
    resourceType?: string | null;
    resourceId?: string | null;
    detail?: Record<string, unknown> | null;
    ipAddress?: string | null;
    userAgent?: string | null;
  }): Promise<unknown>;
}

export interface FavouriteCodesServiceDeps {
  repo: FavouriteCodesRepository;
  hscLookup: HscCodeLookup;
  modifierLookup: ModifierLookup;
  claimHistory: ClaimHistoryQuery;
  providerProfile: ProviderProfileQuery;
  specialtyDefaults: SpecialtyDefaultsQuery;
  auditRepo: AuditRepo;
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export interface EnrichedFavourite {
  favouriteId: string;
  providerId: string;
  healthServiceCode: string;
  displayName: string | null;
  sortOrder: number;
  defaultModifiers: string[] | null;
  createdAt: Date;
  description: string;
  baseFee: string | null;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUDIT_CATEGORY = 'mobile';

// ---------------------------------------------------------------------------
// Service functions
// ---------------------------------------------------------------------------

/**
 * Add a favourite code for the physician.
 *
 * Validates:
 * - HSC code exists in Reference Data (Domain 2).
 * - Favourite count < MAX_FAVOURITES (30).
 * - Modifiers (if provided) are known codes.
 *
 * Creates favourite. Audit log: mobile.favourite_added.
 * Returns created favourite with resolved HSC description.
 */
export async function addFavourite(
  deps: FavouriteCodesServiceDeps,
  providerId: string,
  data: {
    healthServiceCode: string;
    displayName?: string;
    defaultModifiers?: string[];
    sortOrder: number;
  },
): Promise<EnrichedFavourite> {
  // 1. Validate HSC code exists
  const hscDetail = await deps.hscLookup.findByCode(data.healthServiceCode);
  if (!hscDetail) {
    throw new ValidationError(
      'Health service code not found in reference data',
    );
  }

  // 2. Validate modifiers are known codes
  if (data.defaultModifiers && data.defaultModifiers.length > 0) {
    for (const mod of data.defaultModifiers) {
      const known = await deps.modifierLookup.isKnownModifier(mod);
      if (!known) {
        throw new ValidationError(`Unknown modifier code: ${mod}`);
      }
    }
  }

  // 3. Create favourite (repo handles max 30 check and duplicate check)
  const favourite = await deps.repo.create({
    providerId,
    healthServiceCode: data.healthServiceCode,
    displayName: data.displayName ?? null,
    sortOrder: data.sortOrder,
    defaultModifiers: data.defaultModifiers ?? null,
  });

  // 4. Audit log
  await deps.auditRepo.appendAuditLog({
    userId: providerId,
    action: MobileAuditAction.FAVOURITE_ADDED,
    category: AUDIT_CATEGORY,
    resourceType: 'favourite_code',
    resourceId: favourite.favouriteId,
    detail: {
      healthServiceCode: data.healthServiceCode,
      displayName: data.displayName ?? null,
      sortOrder: data.sortOrder,
    },
  });

  return {
    favouriteId: favourite.favouriteId,
    providerId: favourite.providerId,
    healthServiceCode: favourite.healthServiceCode,
    displayName: favourite.displayName,
    sortOrder: favourite.sortOrder,
    defaultModifiers: favourite.defaultModifiers,
    createdAt: favourite.createdAt,
    description: hscDetail.description,
    baseFee: hscDetail.baseFee,
  };
}

/**
 * Update a favourite code.
 *
 * Validates ownership (repo scoping). Updates fields.
 * Returns updated favourite.
 */
export async function updateFavourite(
  deps: FavouriteCodesServiceDeps,
  providerId: string,
  favouriteId: string,
  data: {
    displayName?: string;
    defaultModifiers?: string[];
    sortOrder?: number;
  },
): Promise<EnrichedFavourite> {
  // 1. Validate modifiers if provided
  if (data.defaultModifiers && data.defaultModifiers.length > 0) {
    for (const mod of data.defaultModifiers) {
      const known = await deps.modifierLookup.isKnownModifier(mod);
      if (!known) {
        throw new ValidationError(`Unknown modifier code: ${mod}`);
      }
    }
  }

  // 2. Update (repo enforces provider scoping, returns null if not found)
  const updatePayload: Record<string, unknown> = {};
  if (data.displayName !== undefined) updatePayload.displayName = data.displayName;
  if (data.defaultModifiers !== undefined) updatePayload.defaultModifiers = data.defaultModifiers;
  if (data.sortOrder !== undefined) updatePayload.sortOrder = data.sortOrder;

  const updated = await deps.repo.update(favouriteId, providerId, updatePayload);
  if (!updated) {
    throw new NotFoundError('Favourite code');
  }

  // 3. Enrich with HSC description
  const hscDetail = await deps.hscLookup.findByCode(updated.healthServiceCode);

  return {
    favouriteId: updated.favouriteId,
    providerId: updated.providerId,
    healthServiceCode: updated.healthServiceCode,
    displayName: updated.displayName,
    sortOrder: updated.sortOrder,
    defaultModifiers: updated.defaultModifiers,
    createdAt: updated.createdAt,
    description: hscDetail?.description ?? '',
    baseFee: hscDetail?.baseFee ?? null,
  };
}

/**
 * Remove a favourite code.
 *
 * Validates ownership (repo scoping). Deletes.
 * Audit log: mobile.favourite_removed.
 */
export async function removeFavourite(
  deps: FavouriteCodesServiceDeps,
  providerId: string,
  favouriteId: string,
): Promise<void> {
  const deleted = await deps.repo.delete(favouriteId, providerId);
  if (!deleted) {
    throw new NotFoundError('Favourite code');
  }

  await deps.auditRepo.appendAuditLog({
    userId: providerId,
    action: MobileAuditAction.FAVOURITE_REMOVED,
    category: AUDIT_CATEGORY,
    resourceType: 'favourite_code',
    resourceId: favouriteId,
    detail: {},
  });
}

/**
 * Reorder favourites.
 *
 * Validates all IDs belong to provider (repo handles this).
 * Bulk updates sort_order.
 * Audit log: mobile.favourite_reordered.
 */
export async function reorderFavourites(
  deps: FavouriteCodesServiceDeps,
  providerId: string,
  items: Array<{ favourite_id: string; sort_order: number }>,
): Promise<void> {
  // Repo validates ownership and performs bulk update
  await deps.repo.reorder(providerId, items);

  await deps.auditRepo.appendAuditLog({
    userId: providerId,
    action: MobileAuditAction.FAVOURITE_REORDERED,
    category: AUDIT_CATEGORY,
    resourceType: 'favourite_code',
    detail: {
      itemCount: items.length,
    },
  });
}

/**
 * List favourites in sort order.
 *
 * Joins with Reference Data to include HSC code description
 * and fee schedule amount. Returns enriched list.
 */
export async function listFavourites(
  deps: FavouriteCodesServiceDeps,
  providerId: string,
): Promise<EnrichedFavourite[]> {
  const favourites = await deps.repo.listByProvider(providerId);

  const enriched: EnrichedFavourite[] = [];
  for (const fav of favourites) {
    const hscDetail = await deps.hscLookup.findByCode(fav.healthServiceCode);
    enriched.push({
      favouriteId: fav.favouriteId,
      providerId: fav.providerId,
      healthServiceCode: fav.healthServiceCode,
      displayName: fav.displayName,
      sortOrder: fav.sortOrder,
      defaultModifiers: fav.defaultModifiers,
      createdAt: fav.createdAt,
      description: hscDetail?.description ?? '',
      baseFee: hscDetail?.baseFee ?? null,
    });
  }

  return enriched;
}

/**
 * Seed favourites on first mobile use or when list is empty.
 *
 * 1. Check if physician already has favourites — skip if yes.
 * 2. Query claims for top 10 most frequently billed HSC codes.
 * 3. If results found — bulk-create as favourites (sort_order 1–N).
 * 4. If no claim history — get specialty from provider profile,
 *    query specialty-typical codes from Reference Data.
 * 5. Bulk-create from specialty defaults.
 *
 * Returns seeded count.
 */
export async function seedFavourites(
  deps: FavouriteCodesServiceDeps,
  providerId: string,
): Promise<number> {
  // 1. Check if already has favourites
  const existing = await deps.repo.countByProvider(providerId);
  if (existing > 0) {
    return 0;
  }

  // 2. Try claim history first
  const topCodes = await deps.claimHistory.getTopBilledCodes(
    providerId,
    AUTO_SEED_COUNT,
  );

  if (topCodes.length > 0) {
    // 3. Bulk-create from claim history
    const items = topCodes.map((tc, index) => ({
      healthServiceCode: tc.healthServiceCode,
      displayName: null as string | null,
      sortOrder: index + 1,
      defaultModifiers: null as string[] | null,
    }));

    await deps.repo.bulkCreate(providerId, items);

    await deps.auditRepo.appendAuditLog({
      userId: providerId,
      action: MobileAuditAction.FAVOURITE_ADDED,
      category: AUDIT_CATEGORY,
      resourceType: 'favourite_code',
      detail: {
        seedSource: 'claim_history',
        count: topCodes.length,
      },
    });

    return topCodes.length;
  }

  // 4. No claim history — try specialty defaults
  const specialty = await deps.providerProfile.getSpecialty(providerId);
  if (!specialty) {
    return 0;
  }

  const defaultCodes = await deps.specialtyDefaults.getDefaultCodes(specialty);
  if (defaultCodes.length === 0) {
    return 0;
  }

  // 5. Bulk-create from specialty defaults (cap at AUTO_SEED_COUNT)
  const codesToSeed = defaultCodes.slice(0, AUTO_SEED_COUNT);
  const items = codesToSeed.map((code, index) => ({
    healthServiceCode: code,
    displayName: null as string | null,
    sortOrder: index + 1,
    defaultModifiers: null as string[] | null,
  }));

  await deps.repo.bulkCreate(providerId, items);

  await deps.auditRepo.appendAuditLog({
    userId: providerId,
    action: MobileAuditAction.FAVOURITE_ADDED,
    category: AUDIT_CATEGORY,
    resourceType: 'favourite_code',
    detail: {
      seedSource: 'specialty_defaults',
      specialty,
      count: codesToSeed.length,
    },
  });

  return codesToSeed.length;
}
