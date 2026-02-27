import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';

import { setupTestDb, teardownTestDb, getTestDb } from '../fixtures/db.js';
import { withTestTransaction } from '../fixtures/helpers.js';
import { createTestReferenceVersion, createTestUser } from '../fixtures/factories.js';
import { createReferenceRepository } from '../../src/domains/reference/reference.repository.js';

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

let db: NodePgDatabase;

beforeAll(async () => {
  await setupTestDb();
  db = getTestDb();
});

afterAll(async () => {
  await teardownTestDb();
});

/**
 * Helper: create a user + reference version inside a transaction.
 * The reference_data_versions table requires publishedBy (FK to users)
 * and publishedAt, so we create a user first.
 */
async function seedVersion(
  tx: NodePgDatabase,
  overrides: Parameters<typeof createTestReferenceVersion>[1] = {},
) {
  const user = await createTestUser(tx);
  return createTestReferenceVersion(tx, {
    publishedBy: user.userId,
    publishedAt: new Date(),
    ...overrides,
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('reference repository — database integration', () => {
  // -------------------------------------------------------------------------
  // 1. createVersion
  // -------------------------------------------------------------------------

  it('creates a reference version and returns generated fields', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createReferenceRepository(tx);
      const user = await createTestUser(tx);

      const version = await repo.createVersion({
        dataSet: 'somb',
        versionLabel: 'v2026.1',
        effectiveFrom: '2026-01-01',
        isActive: false,
        publishedBy: user.userId,
        publishedAt: new Date(),
      });

      expect(version.versionId).toBeDefined();
      expect(version.dataSet).toBe('somb');
      expect(version.versionLabel).toBe('v2026.1');
      expect(version.effectiveFrom).toBe('2026-01-01');
      expect(version.isActive).toBe(false);
    }));

  // -------------------------------------------------------------------------
  // 2. findActiveVersion + activateVersion
  // -------------------------------------------------------------------------

  it('activates a version and finds it as the active version for the dataset', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createReferenceRepository(tx);
      const version = await seedVersion(tx, {
        dataSet: 'somb',
        isActive: false,
      });

      // Initially no active version
      const before = await repo.findActiveVersion('somb');
      expect(before).toBeUndefined();

      // Activate
      await repo.activateVersion(version.versionId);

      const active = await repo.findActiveVersion('somb');
      expect(active).toBeDefined();
      expect(active!.versionId).toBe(version.versionId);
      expect(active!.isActive).toBe(true);
    }));

  // -------------------------------------------------------------------------
  // 3. activateVersion with previousVersionId deactivates the old version
  // -------------------------------------------------------------------------

  it('deactivates the previous version when activating a new one', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createReferenceRepository(tx);

      const v1 = await seedVersion(tx, {
        dataSet: 'somb',
        versionLabel: 'v2025.1',
        effectiveFrom: '2025-01-01',
        isActive: true,
      });

      const v2 = await seedVersion(tx, {
        dataSet: 'somb',
        versionLabel: 'v2026.1',
        effectiveFrom: '2026-01-01',
        isActive: false,
      });

      await repo.activateVersion(v2.versionId, v1.versionId);

      const versions = await repo.listVersions('somb');
      const activeVersions = versions.filter((v) => v.isActive);

      expect(activeVersions).toHaveLength(1);
      expect(activeVersions[0].versionId).toBe(v2.versionId);

      // Previous version should have effectiveTo set to the new version's effectiveFrom
      const deactivated = versions.find((v) => v.versionId === v1.versionId);
      expect(deactivated!.isActive).toBe(false);
      expect(deactivated!.effectiveTo).toBe('2026-01-01');
    }));

  // -------------------------------------------------------------------------
  // 4. listVersions
  // -------------------------------------------------------------------------

  it('lists all versions for a dataset ordered by effectiveFrom DESC', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createReferenceRepository(tx);

      await seedVersion(tx, {
        dataSet: 'wcb',
        versionLabel: 'v2025.1',
        effectiveFrom: '2025-01-01',
      });
      await seedVersion(tx, {
        dataSet: 'wcb',
        versionLabel: 'v2026.1',
        effectiveFrom: '2026-01-01',
      });
      // Different dataset -- should not appear
      await seedVersion(tx, {
        dataSet: 'somb',
        versionLabel: 'v2026.1',
        effectiveFrom: '2026-01-01',
      });

      const versions = await repo.listVersions('wcb');

      expect(versions).toHaveLength(2);
      // Ordered by effectiveFrom DESC: 2026 first
      expect(versions[0].versionLabel).toBe('v2026.1');
      expect(versions[1].versionLabel).toBe('v2025.1');
    }));

  // -------------------------------------------------------------------------
  // 5. bulkInsertHscCodes + searchHscCodes + findHscByCode
  // -------------------------------------------------------------------------

  it('bulk inserts HSC codes and finds them by code or search', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createReferenceRepository(tx);
      const version = await seedVersion(tx, { dataSet: 'somb' });

      await repo.bulkInsertHscCodes(
        [
          {
            hscCode: '03.01A',
            description: 'Complete history and examination',
            baseFee: '100.00',
            feeType: 'FIXED',
            effectiveFrom: '2026-01-01',
          },
          {
            hscCode: '03.03A',
            description: 'Regional examination',
            baseFee: '55.00',
            feeType: 'FIXED',
            effectiveFrom: '2026-01-01',
          },
        ],
        version.versionId,
      );

      // findHscByCode
      const found = await repo.findHscByCode('03.01A', version.versionId);
      expect(found).toBeDefined();
      expect(found!.hscCode).toBe('03.01A');
      expect(found!.baseFee).toBe('100.00');
      expect(found!.description).toBe('Complete history and examination');

      // searchHscCodes — search by code substring
      const byCode = await repo.searchHscCodes('03.01', version.versionId);
      expect(byCode.length).toBeGreaterThanOrEqual(1);
      expect(byCode.some((r) => r.hscCode === '03.01A')).toBe(true);

      // searchHscCodes — search by description text
      const byText = await repo.searchHscCodes(
        'examination',
        version.versionId,
      );
      expect(byText.length).toBeGreaterThanOrEqual(1);
    }));

  // -------------------------------------------------------------------------
  // 6. bulkInsertWcbCodes + searchWcbCodes
  // -------------------------------------------------------------------------

  it('bulk inserts WCB codes and searches them', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createReferenceRepository(tx);
      const version = await seedVersion(tx, { dataSet: 'wcb' });

      await repo.bulkInsertWcbCodes(
        [
          {
            wcbCode: 'W100',
            description: 'Initial consultation for work injury',
            baseFee: '120.00',
            feeType: 'FIXED',
            effectiveFrom: '2026-01-01',
          },
          {
            wcbCode: 'W200',
            description: 'Follow-up visit for work injury',
            baseFee: '65.00',
            feeType: 'FIXED',
            effectiveFrom: '2026-01-01',
          },
        ],
        version.versionId,
      );

      // Search by code
      const results = await repo.searchWcbCodes('W100', version.versionId);
      expect(results.length).toBeGreaterThanOrEqual(1);
      expect(results[0].wcbCode).toBe('W100');

      // Search by description
      const byDesc = await repo.searchWcbCodes(
        'consultation',
        version.versionId,
      );
      expect(byDesc.length).toBeGreaterThanOrEqual(1);

      // findWcbByCode
      const single = await repo.findWcbByCode('W200', version.versionId);
      expect(single).toBeDefined();
      expect(single!.baseFee).toBe('65.00');
    }));

  // -------------------------------------------------------------------------
  // 7. bulkInsertFunctionalCentres + listFunctionalCentres + findFunctionalCentre
  // -------------------------------------------------------------------------

  it('bulk inserts functional centres and retrieves them', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createReferenceRepository(tx);
      const version = await seedVersion(tx, {
        dataSet: 'functional_centres',
      });

      await repo.bulkInsertFunctionalCentres(
        [
          {
            code: 'FC001',
            name: 'Edmonton General Hospital',
            facilityType: 'HOSPITAL',
            locationCity: 'Edmonton',
            locationRegion: 'Edmonton Zone',
            effectiveFrom: '2026-01-01',
          },
          {
            code: 'FC002',
            name: 'Calgary Community Clinic',
            facilityType: 'CLINIC',
            locationCity: 'Calgary',
            locationRegion: 'Calgary Zone',
            effectiveFrom: '2026-01-01',
          },
        ],
        version.versionId,
      );

      // listFunctionalCentres — all
      const all = await repo.listFunctionalCentres(version.versionId);
      expect(all).toHaveLength(2);

      // listFunctionalCentres — filter by facilityType
      const hospitals = await repo.listFunctionalCentres(
        version.versionId,
        'HOSPITAL',
      );
      expect(hospitals).toHaveLength(1);
      expect(hospitals[0].code).toBe('FC001');

      // findFunctionalCentre
      const centre = await repo.findFunctionalCentre(
        'FC002',
        version.versionId,
      );
      expect(centre).toBeDefined();
      expect(centre!.name).toBe('Calgary Community Clinic');
      expect(centre!.facilityType).toBe('CLINIC');
    }));

  // -------------------------------------------------------------------------
  // 8. bulkInsertPcpcmBaskets + findPcpcmBasket
  // -------------------------------------------------------------------------

  it('bulk inserts PCPCM baskets and looks up a basket by HSC code', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createReferenceRepository(tx);
      const version = await seedVersion(tx, { dataSet: 'pcpcm' });

      await repo.bulkInsertPcpcmBaskets(
        [
          {
            hscCode: '03.01A',
            basket: 'A',
            effectiveFrom: '2026-01-01',
          },
          {
            hscCode: '08.19A',
            basket: 'B',
            effectiveFrom: '2026-01-01',
          },
          {
            hscCode: '13.99Z',
            basket: 'C',
            effectiveFrom: '2026-01-01',
          },
        ],
        version.versionId,
      );

      const basketA = await repo.findPcpcmBasket('03.01A', version.versionId);
      expect(basketA).toBeDefined();
      expect(basketA!.basket).toBe('A');

      const basketB = await repo.findPcpcmBasket('08.19A', version.versionId);
      expect(basketB).toBeDefined();
      expect(basketB!.basket).toBe('B');

      // Non-existent code returns undefined
      const missing = await repo.findPcpcmBasket(
        '99.99Z',
        version.versionId,
      );
      expect(missing).toBeUndefined();
    }));
});
