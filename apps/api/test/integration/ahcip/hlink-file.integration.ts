import { describe, it, expect, vi } from 'vitest';
import { createHash } from 'node:crypto';
import {
  formatHlinkHeader,
  formatHlinkClaimRecord,
  formatHlinkTrailer,
  computeChecksum,
  generateHlinkFile,
  type BatchCycleDeps,
} from '../../../src/domains/ahcip/ahcip.service.js';
import { AhcipBatchStatus } from '@meritum/shared/constants/ahcip.constants.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PHYSICIAN_ID = '00000000-1111-0000-0000-000000000001';
const BATCH_ID = '00000000-bbbb-0000-0000-000000000001';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeClaimRecord(overrides: {
  dateOfService?: string;
  baNumber?: string;
  healthServiceCode?: string;
  modifier1?: string | null;
  modifier2?: string | null;
  modifier3?: string | null;
  diagnosticCode?: string | null;
  facilityNumber?: string | null;
  referralPractitioner?: string | null;
  calls?: number;
  timeSpent?: number | null;
  submittedFee?: string | null;
} = {}) {
  return {
    claim: {
      claimId: '00000000-cccc-0000-0000-000000000001',
      physicianId: PHYSICIAN_ID,
      patientId: '00000000-aaaa-0000-0000-000000000001',
      claimType: 'AHCIP',
      state: 'SUBMITTED',
      dateOfService: overrides.dateOfService ?? '2026-01-15',
      submittedBatchId: BATCH_ID,
      createdAt: new Date(),
      updatedAt: new Date(),
      deletedAt: null,
    },
    detail: {
      ahcipDetailId: '00000000-dddd-0000-0000-000000000001',
      claimId: '00000000-cccc-0000-0000-000000000001',
      baNumber: overrides.baNumber ?? '12345',
      healthServiceCode: overrides.healthServiceCode ?? '03.04A',
      modifier1: overrides.modifier1 ?? null,
      modifier2: overrides.modifier2 ?? null,
      modifier3: overrides.modifier3 ?? null,
      diagnosticCode: overrides.diagnosticCode ?? null,
      facilityNumber: overrides.facilityNumber ?? null,
      referralPractitioner: overrides.referralPractitioner ?? null,
      calls: overrides.calls ?? 1,
      timeSpent: overrides.timeSpent ?? null,
      submittedFee: overrides.submittedFee ?? '38.56',
      shadowBillingFlag: false,
      pcpcmBasketFlag: false,
      afterHoursFlag: false,
      afterHoursType: null,
      encounterType: 'FOLLOW_UP',
    },
  };
}

function makeBatch(overrides: Record<string, unknown> = {}) {
  return {
    ahcipBatchId: BATCH_ID,
    physicianId: PHYSICIAN_ID,
    baNumber: '12345',
    batchWeek: '2026-02-19',
    status: AhcipBatchStatus.ASSEMBLING,
    claimCount: 2,
    totalSubmittedValue: '77.12',
    filePath: null,
    fileHash: null,
    submissionReference: null,
    submittedAt: null,
    responseReceivedAt: null,
    createdAt: new Date(),
    createdBy: PHYSICIAN_ID,
    ...overrides,
  };
}

function createMockBatchCycleDeps(
  claims: ReturnType<typeof makeClaimRecord>[],
  batch = makeBatch(),
): BatchCycleDeps {
  return {
    repo: {
      createAhcipDetail: vi.fn(async () => ({})),
      findAhcipDetailByClaimId: vi.fn(async () => null),
      updateAhcipDetail: vi.fn(async () => undefined),
      findAhcipClaimWithDetails: vi.fn(async () => null),
      listAhcipClaimsForBatch: vi.fn(async () => claims),
      updateAssessmentResult: vi.fn(async () => undefined),
      createAhcipBatch: vi.fn(async () => batch),
      findBatchById: vi.fn(async (batchId: string, physicianId: string) => {
        if (batchId === BATCH_ID && physicianId === PHYSICIAN_ID) {
          return batch;
        }
        return null;
      }),
      updateBatchStatus: vi.fn(async () => undefined),
      listBatches: vi.fn(async () => ({
        data: [],
        pagination: { total: 0, page: 1, pageSize: 20, hasMore: false },
      })),
      findNextBatchPreview: vi.fn(async () => []),
      findBatchesAwaitingResponse: vi.fn(async () => []),
      findClaimsByBatchId: vi.fn(async () => []),
      findBatchByWeek: vi.fn(async () => null),
      linkClaimsToBatch: vi.fn(async () => 0),
    } as any,
    feeRefData: {
      getHscDetail: vi.fn(async () => null),
      getModifierFeeImpact: vi.fn(async () => null),
      getAfterHoursPremium: vi.fn(async () => null),
      getCmgpPremium: vi.fn(async () => null),
      getRrnpPremium: vi.fn(async () => null),
      getEdSurcharge: vi.fn(async () => null),
    },
    feeProviderService: {
      isRrnpEligible: vi.fn(async () => false),
    },
    claimStateService: {
      transitionState: vi.fn(async () => true),
    },
    notificationService: {
      emit: vi.fn(async () => {}),
    },
    hlinkTransmission: {
      transmit: vi.fn(async () => ({ submissionReference: 'REF-001' })),
    },
    fileEncryption: {
      encryptAndStore: vi.fn(async () => ({
        filePath: '/tmp/test.enc',
        fileHash: 'abc123',
      })),
    },
    submissionPreferences: {
      getAutoSubmissionMode: vi.fn(async () => 'REQUIRE_APPROVAL' as const),
    },
    validationRunner: {
      validateClaim: vi.fn(async () => ({ passed: true, errors: [] })),
    },
  };
}

// ===========================================================================
// Tests — Unit tests for H-Link format functions
// ===========================================================================

describe('H-Link File Format Functions', () => {
  // =========================================================================
  // Header format
  // =========================================================================

  describe('formatHlinkHeader', () => {
    it('generates correct header with submitter prefix, date, count, vendor ID', () => {
      const header = formatHlinkHeader('MERITUM', '2026-02-19', 5, 'MERITUM_V1');

      expect(header).toBe('H|MERITUM|2026-02-19|000005|MERITUM_V1');
    });

    it('pads record count to 6 digits', () => {
      const header = formatHlinkHeader('MERITUM', '2026-02-19', 1, 'MERITUM_V1');
      expect(header).toContain('|000001|');

      const header2 = formatHlinkHeader('MERITUM', '2026-02-19', 999, 'MERITUM_V1');
      expect(header2).toContain('|000999|');
    });

    it('handles large record counts', () => {
      const header = formatHlinkHeader('MERITUM', '2026-02-19', 123456, 'MERITUM_V1');
      expect(header).toContain('|123456|');
    });

    it('uses pipe delimiter', () => {
      const header = formatHlinkHeader('MERITUM', '2026-02-19', 10, 'MERITUM_V1');
      const parts = header.split('|');
      expect(parts).toHaveLength(5);
      expect(parts[0]).toBe('H');
      expect(parts[1]).toBe('MERITUM');
      expect(parts[2]).toBe('2026-02-19');
      expect(parts[3]).toBe('000010');
      expect(parts[4]).toBe('MERITUM_V1');
    });
  });

  // =========================================================================
  // Claim record format
  // =========================================================================

  describe('formatHlinkClaimRecord', () => {
    it('formats a complete claim record with all fields', () => {
      const record = formatHlinkClaimRecord(
        { dateOfService: '2026-01-15' },
        {
          baNumber: '12345',
          healthServiceCode: '03.04A',
          modifier1: 'AFHR',
          modifier2: 'CMGP',
          modifier3: null,
          diagnosticCode: '780.6',
          facilityNumber: 'FAC001',
          referralPractitioner: 'REF123',
          calls: 1,
          timeSpent: 30,
          submittedFee: '38.56',
        },
      );

      expect(record).toBe('C|12345|03.04A|2026-01-15|AFHR|CMGP||780.6|FAC001|REF123|1|30|38.56');
    });

    it('handles empty optional fields correctly', () => {
      const record = formatHlinkClaimRecord(
        { dateOfService: '2026-01-15' },
        {
          baNumber: '12345',
          healthServiceCode: '03.04A',
          modifier1: null,
          modifier2: null,
          modifier3: null,
          diagnosticCode: null,
          facilityNumber: null,
          referralPractitioner: null,
          calls: 1,
          timeSpent: null,
          submittedFee: '38.56',
        },
      );

      expect(record).toBe('C|12345|03.04A|2026-01-15|||||||1||38.56');
    });

    it('handles null submitted fee as 0.00', () => {
      const record = formatHlinkClaimRecord(
        { dateOfService: '2026-01-15' },
        {
          baNumber: '12345',
          healthServiceCode: '03.04A',
          modifier1: null,
          modifier2: null,
          modifier3: null,
          diagnosticCode: null,
          facilityNumber: null,
          referralPractitioner: null,
          calls: 1,
          timeSpent: null,
          submittedFee: null,
        },
      );

      expect(record).toContain('|0.00');
    });

    it('handles special characters in fields', () => {
      const record = formatHlinkClaimRecord(
        { dateOfService: '2026-01-15' },
        {
          baNumber: '12345',
          healthServiceCode: '13.99H',
          modifier1: 'AFHR',
          modifier2: null,
          modifier3: null,
          diagnosticCode: null,
          facilityNumber: null,
          referralPractitioner: null,
          calls: 1,
          timeSpent: null,
          submittedFee: '10.00',
        },
      );

      // 13.99H contains a dot and letter — should be preserved
      expect(record).toContain('|13.99H|');
    });

    it('uses pipe delimiter with C prefix', () => {
      const record = formatHlinkClaimRecord(
        { dateOfService: '2026-01-15' },
        {
          baNumber: '12345',
          healthServiceCode: '03.04A',
          modifier1: null,
          modifier2: null,
          modifier3: null,
          diagnosticCode: null,
          facilityNumber: null,
          referralPractitioner: null,
          calls: 1,
          timeSpent: null,
          submittedFee: '38.56',
        },
      );

      const parts = record.split('|');
      expect(parts[0]).toBe('C');
      expect(parts).toHaveLength(13);
    });

    it('includes all three modifier slots even when only first is set', () => {
      const record = formatHlinkClaimRecord(
        { dateOfService: '2026-01-15' },
        {
          baNumber: '12345',
          healthServiceCode: '03.04A',
          modifier1: 'TM',
          modifier2: null,
          modifier3: null,
          diagnosticCode: null,
          facilityNumber: null,
          referralPractitioner: null,
          calls: 1,
          timeSpent: null,
          submittedFee: '0.00',
        },
      );

      const parts = record.split('|');
      expect(parts[4]).toBe('TM');
      expect(parts[5]).toBe('');
      expect(parts[6]).toBe('');
    });
  });

  // =========================================================================
  // Trailer format
  // =========================================================================

  describe('formatHlinkTrailer', () => {
    it('generates correct trailer with count, value, and checksum', () => {
      const trailer = formatHlinkTrailer(5, '500.00', 'abc123def456');

      expect(trailer).toBe('T|000005|500.00|abc123def456');
    });

    it('pads record count to 6 digits', () => {
      const trailer = formatHlinkTrailer(1, '38.56', 'checksum1234');
      expect(trailer).toContain('|000001|');
    });

    it('trailer record count matches header record count', () => {
      const count = 42;
      const header = formatHlinkHeader('MERITUM', '2026-02-19', count, 'MERITUM_V1');
      const trailer = formatHlinkTrailer(count, '1000.00', 'checksum1234');

      // Extract count from both
      const headerCount = header.split('|')[3];
      const trailerCount = trailer.split('|')[1];
      expect(headerCount).toBe(trailerCount);
    });
  });

  // =========================================================================
  // Checksum
  // =========================================================================

  describe('computeChecksum', () => {
    it('produces a 16-char hex string', () => {
      const checksum = computeChecksum('H|header', ['C|record1', 'C|record2']);

      expect(checksum).toHaveLength(16);
      expect(checksum).toMatch(/^[0-9a-f]{16}$/);
    });

    it('is deterministic (same input yields same output)', () => {
      const header = 'H|MERITUM|2026-02-19|000002|MERITUM_V1';
      const records = ['C|12345|03.04A|2026-01-15||||||||1||38.56'];

      const checksum1 = computeChecksum(header, records);
      const checksum2 = computeChecksum(header, records);

      expect(checksum1).toBe(checksum2);
    });

    it('changes when records change', () => {
      const header = 'H|MERITUM|2026-02-19|000001|MERITUM_V1';

      const checksum1 = computeChecksum(header, ['C|12345|03.04A|2026-01-15||||||||1||38.56']);
      const checksum2 = computeChecksum(header, ['C|12345|08.19A|2026-01-15||||||||1||50.00']);

      expect(checksum1).not.toBe(checksum2);
    });

    it('is derived from SHA-256 hash', () => {
      const header = 'H|MERITUM|2026-02-19|000001|MERITUM_V1';
      const records = ['C|12345|03.04A|2026-01-15||||||||1||38.56'];

      const content = [header, ...records].join('\n');
      const expected = createHash('sha256').update(content).digest('hex').substring(0, 16);

      const checksum = computeChecksum(header, records);

      expect(checksum).toBe(expected);
    });
  });
});

// ===========================================================================
// Tests — Full H-Link file generation via generateHlinkFile
// ===========================================================================

describe('H-Link File Generation (generateHlinkFile)', () => {
  // =========================================================================
  // Correct file structure
  // =========================================================================

  describe('File structure', () => {
    it('generates file with header, records, and trailer', async () => {
      const claims = [
        makeClaimRecord({ dateOfService: '2026-01-15', submittedFee: '38.56' }),
        makeClaimRecord({
          dateOfService: '2026-01-16',
          submittedFee: '38.56',
          healthServiceCode: '03.01A',
        }),
      ];
      claims[1].claim.claimId = '00000000-cccc-0000-0000-000000000002';
      claims[1].detail.ahcipDetailId = '00000000-dddd-0000-0000-000000000002';
      claims[1].detail.claimId = '00000000-cccc-0000-0000-000000000002';

      const deps = createMockBatchCycleDeps(claims);
      const result = await generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID);

      expect(result.header).toBeTruthy();
      expect(result.records).toHaveLength(2);
      expect(result.trailer).toBeTruthy();
      expect(result.raw).toBeInstanceOf(Buffer);
    });

    it('header starts with H|', async () => {
      const claims = [makeClaimRecord()];
      const deps = createMockBatchCycleDeps(claims);

      const result = await generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID);

      expect(result.header).toMatch(/^H\|/);
    });

    it('all records start with C|', async () => {
      const claims = [
        makeClaimRecord({ dateOfService: '2026-01-15' }),
        makeClaimRecord({ dateOfService: '2026-01-16' }),
      ];
      claims[1].claim.claimId = '00000000-cccc-0000-0000-000000000002';
      claims[1].detail.claimId = '00000000-cccc-0000-0000-000000000002';

      const deps = createMockBatchCycleDeps(claims);
      const result = await generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID);

      for (const record of result.records) {
        expect(record).toMatch(/^C\|/);
      }
    });

    it('trailer starts with T|', async () => {
      const claims = [makeClaimRecord()];
      const deps = createMockBatchCycleDeps(claims);

      const result = await generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID);

      expect(result.trailer).toMatch(/^T\|/);
    });
  });

  // =========================================================================
  // Header correctness
  // =========================================================================

  describe('Header correctness', () => {
    it('contains correct submitter prefix', async () => {
      const claims = [makeClaimRecord()];
      const deps = createMockBatchCycleDeps(claims);

      const result = await generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID);

      const parts = result.header.split('|');
      // Submitter prefix should be present (MERITUM or from env)
      expect(parts[1]).toBeTruthy();
    });

    it('contains correct batch date', async () => {
      const claims = [makeClaimRecord()];
      const batch = makeBatch({ batchWeek: '2026-02-19' });
      const deps = createMockBatchCycleDeps(claims, batch);

      const result = await generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID);

      const parts = result.header.split('|');
      expect(parts[2]).toBe('2026-02-19');
    });

    it('contains correct record count', async () => {
      const claims = [
        makeClaimRecord({ dateOfService: '2026-01-15' }),
        makeClaimRecord({ dateOfService: '2026-01-16' }),
        makeClaimRecord({ dateOfService: '2026-01-17' }),
      ];
      claims[1].claim.claimId = '00000000-cccc-0000-0000-000000000002';
      claims[1].detail.claimId = '00000000-cccc-0000-0000-000000000002';
      claims[2].claim.claimId = '00000000-cccc-0000-0000-000000000003';
      claims[2].detail.claimId = '00000000-cccc-0000-0000-000000000003';

      const deps = createMockBatchCycleDeps(claims);
      const result = await generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID);

      const parts = result.header.split('|');
      expect(parts[3]).toBe('000003');
    });

    it('contains vendor ID', async () => {
      const claims = [makeClaimRecord()];
      const deps = createMockBatchCycleDeps(claims);

      const result = await generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID);

      const parts = result.header.split('|');
      expect(parts[4]).toBeTruthy();
    });
  });

  // =========================================================================
  // Trailer correctness
  // =========================================================================

  describe('Trailer correctness', () => {
    it('record count matches header', async () => {
      const claims = [
        makeClaimRecord({ dateOfService: '2026-01-15' }),
        makeClaimRecord({ dateOfService: '2026-01-16' }),
      ];
      claims[1].claim.claimId = '00000000-cccc-0000-0000-000000000002';
      claims[1].detail.claimId = '00000000-cccc-0000-0000-000000000002';

      const deps = createMockBatchCycleDeps(claims);
      const result = await generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID);

      const headerCount = result.header.split('|')[3];
      const trailerCount = result.trailer.split('|')[1];
      expect(trailerCount).toBe(headerCount);
    });

    it('total value checksum is correct', async () => {
      const claims = [
        makeClaimRecord({ dateOfService: '2026-01-15', submittedFee: '38.56' }),
        makeClaimRecord({ dateOfService: '2026-01-16', submittedFee: '50.00' }),
      ];
      claims[1].claim.claimId = '00000000-cccc-0000-0000-000000000002';
      claims[1].detail.claimId = '00000000-cccc-0000-0000-000000000002';

      const deps = createMockBatchCycleDeps(claims);
      const result = await generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID);

      const trailerParts = result.trailer.split('|');
      // Total value should be sum of fees: 38.56 + 50.00 = 88.56
      expect(trailerParts[2]).toBe('88.56');
    });

    it('checksum is a 16-char hex string', async () => {
      const claims = [makeClaimRecord()];
      const deps = createMockBatchCycleDeps(claims);

      const result = await generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID);

      const trailerParts = result.trailer.split('|');
      const checksum = trailerParts[3];
      expect(checksum).toHaveLength(16);
      expect(checksum).toMatch(/^[0-9a-f]{16}$/);
    });

    it('checksum matches recomputed value', async () => {
      const claims = [makeClaimRecord()];
      const deps = createMockBatchCycleDeps(claims);

      const result = await generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID);

      const expectedChecksum = computeChecksum(result.header, result.records);
      const trailerChecksum = result.trailer.split('|')[3];
      expect(trailerChecksum).toBe(expectedChecksum);
    });
  });

  // =========================================================================
  // Claim ordering
  // =========================================================================

  describe('Claim ordering', () => {
    it('orders claims by date of service ascending', async () => {
      const claims = [
        makeClaimRecord({ dateOfService: '2026-01-20', healthServiceCode: '03.04A' }),
        makeClaimRecord({ dateOfService: '2026-01-10', healthServiceCode: '08.19A' }),
        makeClaimRecord({ dateOfService: '2026-01-15', healthServiceCode: '03.01A' }),
      ];
      claims[0].claim.claimId = '00000000-cccc-0000-0000-000000000001';
      claims[0].detail.claimId = '00000000-cccc-0000-0000-000000000001';
      claims[1].claim.claimId = '00000000-cccc-0000-0000-000000000002';
      claims[1].detail.claimId = '00000000-cccc-0000-0000-000000000002';
      claims[2].claim.claimId = '00000000-cccc-0000-0000-000000000003';
      claims[2].detail.claimId = '00000000-cccc-0000-0000-000000000003';

      const deps = createMockBatchCycleDeps(claims);
      const result = await generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID);

      // Records should be sorted: 2026-01-10, 2026-01-15, 2026-01-20
      expect(result.records[0]).toContain('2026-01-10');
      expect(result.records[1]).toContain('2026-01-15');
      expect(result.records[2]).toContain('2026-01-20');
    });

    it('preserves order for claims on same DOS', async () => {
      const claims = [
        makeClaimRecord({ dateOfService: '2026-01-15', healthServiceCode: '03.04A' }),
        makeClaimRecord({ dateOfService: '2026-01-15', healthServiceCode: '08.19A' }),
      ];
      claims[0].claim.claimId = '00000000-cccc-0000-0000-000000000001';
      claims[0].detail.claimId = '00000000-cccc-0000-0000-000000000001';
      claims[1].claim.claimId = '00000000-cccc-0000-0000-000000000002';
      claims[1].detail.claimId = '00000000-cccc-0000-0000-000000000002';

      const deps = createMockBatchCycleDeps(claims);
      const result = await generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID);

      expect(result.records).toHaveLength(2);
      // Both have same DOS, both should appear
      expect(result.records[0]).toContain('2026-01-15');
      expect(result.records[1]).toContain('2026-01-15');
    });
  });

  // =========================================================================
  // Empty optional fields
  // =========================================================================

  describe('Empty optional fields', () => {
    it('optional fields rendered as empty between pipes', async () => {
      const claims = [
        makeClaimRecord({
          modifier1: null,
          modifier2: null,
          modifier3: null,
          diagnosticCode: null,
          facilityNumber: null,
          referralPractitioner: null,
          timeSpent: null,
        }),
      ];
      const deps = createMockBatchCycleDeps(claims);

      const result = await generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID);

      const recordParts = result.records[0].split('|');
      // modifier1, modifier2, modifier3
      expect(recordParts[4]).toBe('');
      expect(recordParts[5]).toBe('');
      expect(recordParts[6]).toBe('');
      // diagnosticCode
      expect(recordParts[7]).toBe('');
      // facilityNumber
      expect(recordParts[8]).toBe('');
      // referralPractitioner
      expect(recordParts[9]).toBe('');
      // timeSpent
      expect(recordParts[11]).toBe('');
    });
  });

  // =========================================================================
  // Raw buffer
  // =========================================================================

  describe('Raw buffer', () => {
    it('raw content is a UTF-8 Buffer', async () => {
      const claims = [makeClaimRecord()];
      const deps = createMockBatchCycleDeps(claims);

      const result = await generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID);

      expect(result.raw).toBeInstanceOf(Buffer);
      const str = result.raw.toString('utf-8');
      expect(str).toContain(result.header);
      expect(str).toContain(result.trailer);
    });

    it('raw content has newline-separated lines ending with newline', async () => {
      const claims = [makeClaimRecord()];
      const deps = createMockBatchCycleDeps(claims);

      const result = await generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID);

      const str = result.raw.toString('utf-8');
      expect(str).toMatch(/\n$/); // ends with newline
      const lines = str.trim().split('\n');
      expect(lines).toHaveLength(3); // header + 1 record + trailer
    });
  });

  // =========================================================================
  // File encryption and storage
  // =========================================================================

  describe('File encryption and storage', () => {
    it('encrypts and stores the generated file', async () => {
      const claims = [makeClaimRecord()];
      const deps = createMockBatchCycleDeps(claims);

      await generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID);

      expect(deps.fileEncryption.encryptAndStore).toHaveBeenCalledTimes(1);
      const [content, filename] = (deps.fileEncryption.encryptAndStore as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(content).toBeInstanceOf(Buffer);
      expect(filename).toContain('hlink_');
      expect(filename).toContain('12345'); // ba_number
      expect(filename).toContain('2026-02-19'); // batch_week
    });

    it('updates batch status to GENERATED', async () => {
      const claims = [makeClaimRecord()];
      const deps = createMockBatchCycleDeps(claims);

      await generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID);

      expect(deps.repo.updateBatchStatus).toHaveBeenCalledWith(
        BATCH_ID,
        PHYSICIAN_ID,
        AhcipBatchStatus.GENERATED,
        expect.objectContaining({
          filePath: '/tmp/test.enc',
          fileHash: 'abc123',
        }),
      );
    });
  });

  // =========================================================================
  // Error handling
  // =========================================================================

  describe('Error handling', () => {
    it('throws when batch not found', async () => {
      const claims = [makeClaimRecord()];
      const deps = createMockBatchCycleDeps(claims);

      await expect(
        generateHlinkFile(deps, '00000000-9999-0000-0000-000000000099', PHYSICIAN_ID),
      ).rejects.toThrow('Batch not found');
    });

    it('throws when batch is not in ASSEMBLING status', async () => {
      const claims = [makeClaimRecord()];
      const batch = makeBatch({ status: AhcipBatchStatus.SUBMITTED });
      const deps = createMockBatchCycleDeps(claims, batch);

      await expect(
        generateHlinkFile(deps, BATCH_ID, PHYSICIAN_ID),
      ).rejects.toThrow('Cannot generate file');
    });
  });
});
