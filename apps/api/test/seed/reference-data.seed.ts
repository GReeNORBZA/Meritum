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
// Tests — SOMB Reference Data Seeding Pipeline
// ---------------------------------------------------------------------------

describe('reference data seeding pipeline', () => {
  // -------------------------------------------------------------------------
  // 1. Version creation
  // -------------------------------------------------------------------------

  it('creates a version with all required fields populated', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createReferenceRepository(tx);
      const user = await createTestUser(tx);

      const version = await repo.createVersion({
        dataSet: 'hsc_codes',
        versionLabel: 'v2026.1',
        effectiveFrom: '2026-01-01',
        isActive: false,
        publishedBy: user.userId,
        publishedAt: new Date(),
      });

      expect(version.versionId).toBeDefined();
      expect(typeof version.versionId).toBe('string');
      expect(version.dataSet).toBe('hsc_codes');
      expect(version.versionLabel).toBe('v2026.1');
      expect(version.effectiveFrom).toBe('2026-01-01');
      expect(version.isActive).toBe(false);
      expect(version.publishedBy).toBe(user.userId);
      expect(version.createdAt).toBeInstanceOf(Date);
    }));

  // -------------------------------------------------------------------------
  // 2. HSC code bulk insert
  // -------------------------------------------------------------------------

  it('bulk inserts HSC codes and verifies lookup by code', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createReferenceRepository(tx);
      const version = await seedVersion(tx, { dataSet: 'hsc_codes' });

      const codes = Array.from({ length: 100 }, (_, i) => ({
        hscCode: `HSC${String(i).padStart(4, '0')}`,
        description: `Health service code ${i}`,
        baseFee: String(50 + i),
        feeType: 'FIXED',
        effectiveFrom: '2026-01-01',
      }));

      await repo.bulkInsertHscCodes(codes, version.versionId);

      const found = await repo.findHscByCode('HSC0050', version.versionId);
      expect(found).toBeDefined();
      expect(found!.hscCode).toBe('HSC0050');
      expect(found!.description).toBe('Health service code 50');
      expect(found!.baseFee).toBe('100');

      // Verify first and last
      const first = await repo.findHscByCode('HSC0000', version.versionId);
      expect(first).toBeDefined();
      expect(first!.baseFee).toBe('50');

      const last = await repo.findHscByCode('HSC0099', version.versionId);
      expect(last).toBeDefined();
      expect(last!.baseFee).toBe('149');

      // Non-existent code returns undefined
      const missing = await repo.findHscByCode('HSC9999', version.versionId);
      expect(missing).toBeUndefined();
    }));

  // -------------------------------------------------------------------------
  // 3. WCB code bulk insert
  // -------------------------------------------------------------------------

  it('bulk inserts WCB codes and verifies lookup', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createReferenceRepository(tx);
      const version = await seedVersion(tx, { dataSet: 'wcb_codes' });

      const codes = Array.from({ length: 25 }, (_, i) => ({
        wcbCode: `WCB${String(i).padStart(3, '0')}`,
        description: `Workers compensation procedure ${i}`,
        baseFee: String(75 + i * 5),
        feeType: 'FIXED',
        effectiveFrom: '2026-01-01',
      }));

      await repo.bulkInsertWcbCodes(codes, version.versionId);

      const found = await repo.findWcbByCode('WCB010', version.versionId);
      expect(found).toBeDefined();
      expect(found!.wcbCode).toBe('WCB010');
      expect(found!.description).toBe('Workers compensation procedure 10');
      expect(found!.baseFee).toBe('125');

      // Search by description text
      const results = await repo.searchWcbCodes(
        'compensation',
        version.versionId,
      );
      expect(results.length).toBeGreaterThanOrEqual(1);
    }));

  // -------------------------------------------------------------------------
  // 4. Functional centre seeding
  // -------------------------------------------------------------------------

  it('bulk inserts functional centres and retrieves them by code', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createReferenceRepository(tx);
      const version = await seedVersion(tx, {
        dataSet: 'functional_centres',
      });

      const centres = [
        {
          code: 'HOSP001',
          name: 'Royal Alexandra Hospital',
          facilityType: 'HOSPITAL',
          locationCity: 'Edmonton',
          locationRegion: 'Edmonton Zone',
          effectiveFrom: '2026-01-01',
        },
        {
          code: 'CLIN001',
          name: 'Southgate Medical Clinic',
          facilityType: 'CLINIC',
          locationCity: 'Edmonton',
          locationRegion: 'Edmonton Zone',
          effectiveFrom: '2026-01-01',
        },
        {
          code: 'HOSP002',
          name: 'Foothills Medical Centre',
          facilityType: 'HOSPITAL',
          locationCity: 'Calgary',
          locationRegion: 'Calgary Zone',
          effectiveFrom: '2026-01-01',
        },
      ];

      await repo.bulkInsertFunctionalCentres(centres, version.versionId);

      // Find by exact code
      const centre = await repo.findFunctionalCentre(
        'HOSP001',
        version.versionId,
      );
      expect(centre).toBeDefined();
      expect(centre!.name).toBe('Royal Alexandra Hospital');
      expect(centre!.facilityType).toBe('HOSPITAL');

      // List all
      const all = await repo.listFunctionalCentres(version.versionId);
      expect(all).toHaveLength(3);

      // List filtered by facility type
      const hospitals = await repo.listFunctionalCentres(
        version.versionId,
        'HOSPITAL',
      );
      expect(hospitals).toHaveLength(2);

      // Non-existent code
      const missing = await repo.findFunctionalCentre(
        'NONE999',
        version.versionId,
      );
      expect(missing).toBeUndefined();
    }));

  // -------------------------------------------------------------------------
  // 5. PCPCM basket seeding
  // -------------------------------------------------------------------------

  it('bulk inserts PCPCM baskets and verifies lookup by HSC code', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createReferenceRepository(tx);
      const version = await seedVersion(tx, { dataSet: 'pcpcm' });

      const baskets = [
        { hscCode: '03.01A', basket: 'A', effectiveFrom: '2026-01-01' },
        { hscCode: '03.03A', basket: 'B', effectiveFrom: '2026-01-01' },
        { hscCode: '03.04A', basket: 'A', effectiveFrom: '2026-01-01' },
        { hscCode: '08.19A', basket: 'C', effectiveFrom: '2026-01-01' },
        { hscCode: '13.99Z', basket: 'NOT_IN_BASKET', effectiveFrom: '2026-01-01' },
      ];

      await repo.bulkInsertPcpcmBaskets(baskets, version.versionId);

      const basketA = await repo.findPcpcmBasket('03.01A', version.versionId);
      expect(basketA).toBeDefined();
      expect(basketA!.basket).toBe('A');

      const basketC = await repo.findPcpcmBasket('08.19A', version.versionId);
      expect(basketC).toBeDefined();
      expect(basketC!.basket).toBe('C');

      const notInBasket = await repo.findPcpcmBasket(
        '13.99Z',
        version.versionId,
      );
      expect(notInBasket).toBeDefined();
      expect(notInBasket!.basket).toBe('NOT_IN_BASKET');

      // Non-existent code
      const missing = await repo.findPcpcmBasket('99.99Z', version.versionId);
      expect(missing).toBeUndefined();
    }));

  // -------------------------------------------------------------------------
  // 6. Version activation — only one active at a time
  // -------------------------------------------------------------------------

  it('activating a version deactivates the previous one', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createReferenceRepository(tx);

      const v1 = await seedVersion(tx, {
        dataSet: 'test_ds',
        versionLabel: 'v1',
        effectiveFrom: '2026-01-01',
        isActive: true,
      });
      const v2 = await seedVersion(tx, {
        dataSet: 'test_ds',
        versionLabel: 'v2',
        effectiveFrom: '2026-02-01',
        isActive: false,
      });

      // Before activation, v1 is active
      const activeBefore = await repo.findActiveVersion('test_ds');
      expect(activeBefore?.versionId).toBe(v1.versionId);

      // Activate v2, deactivating v1
      await repo.activateVersion(v2.versionId, v1.versionId);

      const activeAfter = await repo.findActiveVersion('test_ds');
      expect(activeAfter?.versionId).toBe(v2.versionId);

      // Verify only one version is active
      const versions = await repo.listVersions('test_ds');
      const activeVersions = versions.filter((v) => v.isActive);
      expect(activeVersions).toHaveLength(1);
      expect(activeVersions[0].versionId).toBe(v2.versionId);

      // v1 should have effectiveTo set to v2's effectiveFrom
      const deactivated = versions.find((v) => v.versionId === v1.versionId);
      expect(deactivated!.isActive).toBe(false);
      expect(deactivated!.effectiveTo).toBe('2026-02-01');
    }));

  // -------------------------------------------------------------------------
  // 7. Incremental update — v1 data persists after v2 is seeded
  // -------------------------------------------------------------------------

  it('data seeded under v1 remains accessible after v2 is created with different data', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createReferenceRepository(tx);

      const v1 = await seedVersion(tx, {
        dataSet: 'hsc_codes',
        versionLabel: 'v2025.1',
        effectiveFrom: '2025-01-01',
        isActive: true,
      });

      const v2 = await seedVersion(tx, {
        dataSet: 'hsc_codes',
        versionLabel: 'v2026.1',
        effectiveFrom: '2026-01-01',
        isActive: false,
      });

      // Seed v1 with one set of codes
      await repo.bulkInsertHscCodes(
        [
          {
            hscCode: '03.01A',
            description: 'Complete examination (v1)',
            baseFee: '100.00',
            feeType: 'FIXED',
            effectiveFrom: '2025-01-01',
          },
          {
            hscCode: '03.01B',
            description: 'Partial examination (v1 only)',
            baseFee: '60.00',
            feeType: 'FIXED',
            effectiveFrom: '2025-01-01',
          },
        ],
        v1.versionId,
      );

      // Seed v2 with different codes (03.01A updated fee, 03.01B removed, 03.01C new)
      await repo.bulkInsertHscCodes(
        [
          {
            hscCode: '03.01A',
            description: 'Complete examination (v2)',
            baseFee: '110.00',
            feeType: 'FIXED',
            effectiveFrom: '2026-01-01',
          },
          {
            hscCode: '03.01C',
            description: 'Extended examination (v2 only)',
            baseFee: '150.00',
            feeType: 'FIXED',
            effectiveFrom: '2026-01-01',
          },
        ],
        v2.versionId,
      );

      // v1 data is untouched
      const v1Code = await repo.findHscByCode('03.01A', v1.versionId);
      expect(v1Code!.description).toBe('Complete examination (v1)');
      expect(v1Code!.baseFee).toBe('100.00');

      const v1Only = await repo.findHscByCode('03.01B', v1.versionId);
      expect(v1Only).toBeDefined();
      expect(v1Only!.description).toBe('Partial examination (v1 only)');

      // v2 data is separate
      const v2Code = await repo.findHscByCode('03.01A', v2.versionId);
      expect(v2Code!.description).toBe('Complete examination (v2)');
      expect(v2Code!.baseFee).toBe('110.00');

      const v2New = await repo.findHscByCode('03.01C', v2.versionId);
      expect(v2New).toBeDefined();
      expect(v2New!.description).toBe('Extended examination (v2 only)');

      // v1-only code is not visible under v2
      const notInV2 = await repo.findHscByCode('03.01B', v2.versionId);
      expect(notInV2).toBeUndefined();

      // v2-only code is not visible under v1
      const notInV1 = await repo.findHscByCode('03.01C', v1.versionId);
      expect(notInV1).toBeUndefined();
    }));

  // -------------------------------------------------------------------------
  // 8. Code search by description text
  // -------------------------------------------------------------------------

  it('searches HSC codes by partial description text', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createReferenceRepository(tx);
      const version = await seedVersion(tx, { dataSet: 'hsc_codes' });

      await repo.bulkInsertHscCodes(
        [
          {
            hscCode: '03.01A',
            description: 'Complete history and physical examination',
            baseFee: '100.00',
            feeType: 'FIXED',
            effectiveFrom: '2026-01-01',
          },
          {
            hscCode: '03.03A',
            description: 'Regional examination focused assessment',
            baseFee: '55.00',
            feeType: 'FIXED',
            effectiveFrom: '2026-01-01',
          },
          {
            hscCode: '03.04A',
            description: 'Office visit — limited consultation',
            baseFee: '38.56',
            feeType: 'FIXED',
            effectiveFrom: '2026-01-01',
          },
          {
            hscCode: '08.19A',
            description: 'Injection of therapeutic substance',
            baseFee: '25.00',
            feeType: 'FIXED',
            effectiveFrom: '2026-01-01',
          },
        ],
        version.versionId,
      );

      // Search by "examination" — should match 03.01A and 03.03A
      const examResults = await repo.searchHscCodes(
        'examination',
        version.versionId,
      );
      expect(examResults.length).toBeGreaterThanOrEqual(2);
      const examCodes = examResults.map((r) => r.hscCode);
      expect(examCodes).toContain('03.01A');
      expect(examCodes).toContain('03.03A');

      // Search by "injection" — should match 08.19A
      const injectionResults = await repo.searchHscCodes(
        'injection',
        version.versionId,
      );
      expect(injectionResults.length).toBeGreaterThanOrEqual(1);
      expect(injectionResults[0].hscCode).toBe('08.19A');

      // Search by code substring — should match 03.01A
      const codeResults = await repo.searchHscCodes(
        '03.01',
        version.versionId,
      );
      expect(codeResults.length).toBeGreaterThanOrEqual(1);
      expect(codeResults.some((r) => r.hscCode === '03.01A')).toBe(true);
    }));

  // -------------------------------------------------------------------------
  // 9. Large dataset — 5,000 HSC codes
  // -------------------------------------------------------------------------

  it(
    'seeds 5,000 HSC codes without timeout',
    () =>
      withTestTransaction(db, async (tx) => {
        const repo = createReferenceRepository(tx);
        const version = await seedVersion(tx, { dataSet: 'hsc_codes' });

        const codes = Array.from({ length: 5_000 }, (_, i) => ({
          hscCode: `LG${String(i).padStart(5, '0')}`,
          description: `Large dataset service code number ${i}`,
          baseFee: String((10 + (i % 500)).toFixed(2)),
          feeType: i % 3 === 0 ? 'FIXED' : i % 3 === 1 ? 'PERCENTAGE' : 'TIME_BASED',
          effectiveFrom: '2026-01-01',
        }));

        await repo.bulkInsertHscCodes(codes, version.versionId);

        // Verify total count via pagination
        const page = await repo.listHscByVersion(version.versionId, {
          limit: 10,
          offset: 0,
        });
        expect(page.total).toBe(5_000);

        // Spot-check records at the boundaries
        const first = await repo.findHscByCode('LG00000', version.versionId);
        expect(first).toBeDefined();
        expect(first!.description).toBe('Large dataset service code number 0');

        const middle = await repo.findHscByCode('LG02500', version.versionId);
        expect(middle).toBeDefined();
        expect(middle!.description).toBe(
          'Large dataset service code number 2500',
        );

        const last = await repo.findHscByCode('LG04999', version.versionId);
        expect(last).toBeDefined();
        expect(last!.description).toBe(
          'Large dataset service code number 4999',
        );

        // Search still works on large dataset
        const results = await repo.searchHscCodes(
          'LG02500',
          version.versionId,
        );
        expect(results.length).toBeGreaterThanOrEqual(1);
      }),
    { timeout: 30_000 },
  );

  // -------------------------------------------------------------------------
  // 10. Multiple datasets — no cross-contamination
  // -------------------------------------------------------------------------

  it('versions for different datasets do not interfere with each other', () =>
    withTestTransaction(db, async (tx) => {
      const repo = createReferenceRepository(tx);

      // Create versions for two separate datasets
      const hscVersion = await seedVersion(tx, {
        dataSet: 'hsc_codes',
        versionLabel: 'hsc-v1',
        effectiveFrom: '2026-01-01',
        isActive: true,
      });

      const wcbVersion = await seedVersion(tx, {
        dataSet: 'wcb_codes',
        versionLabel: 'wcb-v1',
        effectiveFrom: '2026-01-01',
        isActive: true,
      });

      const fcVersion = await seedVersion(tx, {
        dataSet: 'functional_centres',
        versionLabel: 'fc-v1',
        effectiveFrom: '2026-01-01',
        isActive: true,
      });

      // Seed data into each dataset
      await repo.bulkInsertHscCodes(
        [
          {
            hscCode: '03.01A',
            description: 'HSC service code',
            baseFee: '100.00',
            feeType: 'FIXED',
            effectiveFrom: '2026-01-01',
          },
        ],
        hscVersion.versionId,
      );

      await repo.bulkInsertWcbCodes(
        [
          {
            wcbCode: 'W100',
            description: 'WCB service code',
            baseFee: '120.00',
            feeType: 'FIXED',
            effectiveFrom: '2026-01-01',
          },
        ],
        wcbVersion.versionId,
      );

      await repo.bulkInsertFunctionalCentres(
        [
          {
            code: 'FC001',
            name: 'Test Hospital',
            facilityType: 'HOSPITAL',
            locationCity: 'Edmonton',
            locationRegion: 'Edmonton Zone',
            effectiveFrom: '2026-01-01',
          },
        ],
        fcVersion.versionId,
      );

      // Each dataset has its own active version
      const activeHsc = await repo.findActiveVersion('hsc_codes');
      expect(activeHsc?.versionId).toBe(hscVersion.versionId);

      const activeWcb = await repo.findActiveVersion('wcb_codes');
      expect(activeWcb?.versionId).toBe(wcbVersion.versionId);

      const activeFc = await repo.findActiveVersion('functional_centres');
      expect(activeFc?.versionId).toBe(fcVersion.versionId);

      // listVersions returns only the correct dataset
      const hscVersions = await repo.listVersions('hsc_codes');
      expect(hscVersions).toHaveLength(1);
      expect(hscVersions[0].versionLabel).toBe('hsc-v1');

      const wcbVersions = await repo.listVersions('wcb_codes');
      expect(wcbVersions).toHaveLength(1);
      expect(wcbVersions[0].versionLabel).toBe('wcb-v1');

      // HSC data is not accessible via WCB version and vice versa
      const hscInWcb = await repo.findHscByCode('03.01A', wcbVersion.versionId);
      expect(hscInWcb).toBeUndefined();

      const wcbInHsc = await repo.findWcbByCode('W100', hscVersion.versionId);
      expect(wcbInHsc).toBeUndefined();

      // Functional centres only visible under their own version
      const fcInHsc = await repo.findFunctionalCentre(
        'FC001',
        hscVersion.versionId,
      );
      expect(fcInHsc).toBeUndefined();

      const fcReal = await repo.findFunctionalCentre(
        'FC001',
        fcVersion.versionId,
      );
      expect(fcReal).toBeDefined();
      expect(fcReal!.name).toBe('Test Hospital');
    }));
});
