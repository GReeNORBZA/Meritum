import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as AdmZip from 'adm-zip';

// ---------------------------------------------------------------------------
// Mock drizzle-orm (needed by export.service transitive imports)
// ---------------------------------------------------------------------------

vi.mock('drizzle-orm', () => ({
  eq: () => ({ __predicate: () => true }),
  ne: () => ({ __predicate: () => true }),
  and: () => ({ __predicate: () => true }),
  lte: () => ({ __predicate: () => true }),
  desc: () => ({ __orderBy: () => 0 }),
  asc: () => ({ __orderBy: () => 0 }),
  count: () => ({ __aggregate: 'count' }),
  sum: () => ({ __aggregate: 'sum' }),
  max: () => ({ __aggregate: 'max' }),
  sql: () => ({ __sqlExpr: () => null }),
  isNotNull: () => ({ __predicate: () => true }),
}));

vi.mock('@meritum/shared/schemas/db/platform.schema.js', () => {
  const makeCol = (name: string) => ({ name });
  return {
    subscriptions: { __table: 'subscriptions', subscriptionId: makeCol('subscriptionId'), providerId: makeCol('providerId'), stripeCustomerId: makeCol('stripeCustomerId'), stripeSubscriptionId: makeCol('stripeSubscriptionId'), plan: makeCol('plan'), status: makeCol('status'), currentPeriodStart: makeCol('currentPeriodStart'), currentPeriodEnd: makeCol('currentPeriodEnd'), trialEnd: makeCol('trialEnd'), failedPaymentCount: makeCol('failedPaymentCount'), suspendedAt: makeCol('suspendedAt'), cancelledAt: makeCol('cancelledAt'), deletionScheduledAt: makeCol('deletionScheduledAt'), earlyBirdLockedUntil: makeCol('earlyBirdLockedUntil'), earlyBirdExpiryNotified: makeCol('earlyBirdExpiryNotified'), createdAt: makeCol('createdAt'), updatedAt: makeCol('updatedAt') },
    paymentHistory: { __table: 'payment_history', paymentId: makeCol('paymentId'), subscriptionId: makeCol('subscriptionId'), stripeInvoiceId: makeCol('stripeInvoiceId'), amountCad: makeCol('amountCad'), gstAmount: makeCol('gstAmount'), totalCad: makeCol('totalCad'), status: makeCol('status'), paidAt: makeCol('paidAt'), createdAt: makeCol('createdAt') },
    statusComponents: { __table: 'status_components' },
    statusIncidents: { __table: 'status_incidents' },
    incidentUpdates: { __table: 'incident_updates' },
    practiceMemberships: { __table: 'practice_memberships' },
  };
});

vi.mock('@meritum/shared/constants/platform.constants.js', () => ({
  DUNNING_SUSPENSION_DAY: 14,
  DUNNING_CANCELLATION_DAY: 30,
  EARLY_BIRD_EXPIRY_WARNING_DAYS: 30,
  SubscriptionPlan: {
    STANDARD_MONTHLY: 'STANDARD_MONTHLY',
    STANDARD_ANNUAL: 'STANDARD_ANNUAL',
  },
  PaymentStatus: { PAID: 'PAID', FAILED: 'FAILED', REFUNDED: 'REFUNDED' },
}));

vi.mock('@meritum/shared/constants/iam.constants.js', () => ({
  SubscriptionStatus: {
    TRIAL: 'TRIAL',
    ACTIVE: 'ACTIVE',
    PAST_DUE: 'PAST_DUE',
    SUSPENDED: 'SUSPENDED',
    CANCELLED: 'CANCELLED',
  },
}));

// ---------------------------------------------------------------------------
// Import the export service (after mocks)
// ---------------------------------------------------------------------------

import {
  generateFullPortabilityExport,
  generateClaimsCsv,
  exportWcbClaimsCsv,
  generatePatientsCsv,
  exportAssessmentsCsv,
  exportAnalyticsCsv,
  exportIntelligenceCsv,
  generateFullHiExport,
  type ExportDeps,
  type FullHiExportDeps,
  type ExportAuthContext,
} from '../../../src/domains/platform/export.service.js';
import { type CompleteHealthInformation } from '../../../src/domains/platform/export.repository.js';

// ---------------------------------------------------------------------------
// Mock DB — minimal stub for stubs
// ---------------------------------------------------------------------------

function createMockDb(): any {
  return {} as any;
}

function createExportDeps(): ExportDeps {
  return { db: createMockDb() };
}

// ---------------------------------------------------------------------------
// Expected CSV filenames
// ---------------------------------------------------------------------------

const EXPECTED_FILES = [
  'claims.csv',
  'wcb_claims.csv',
  'patients.csv',
  'assessments.csv',
  'analytics.csv',
  'intelligence.csv',
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('D19-010/011/012/013: Data Portability Export', () => {
  // -------------------------------------------------------------------------
  // Test that generateFullPortabilityExport returns a Buffer
  // -------------------------------------------------------------------------

  it('generateFullPortabilityExport returns a Buffer', async () => {
    const deps = createExportDeps();
    const userId = crypto.randomUUID();

    const result = await generateFullPortabilityExport(deps, userId);

    expect(result).toBeInstanceOf(Buffer);
    expect(result.length).toBeGreaterThan(0);
  });

  // -------------------------------------------------------------------------
  // Test that the ZIP contains 6 CSV files
  // -------------------------------------------------------------------------

  it('ZIP contains exactly 6 CSV files', async () => {
    const deps = createExportDeps();
    const userId = crypto.randomUUID();

    const zipBuffer = await generateFullPortabilityExport(deps, userId);
    const zip = new AdmZip.default(zipBuffer);
    const entries = zip.getEntries();

    expect(entries).toHaveLength(6);

    const fileNames = entries.map((e) => e.entryName).sort();
    expect(fileNames).toEqual(EXPECTED_FILES.sort());
  });

  // -------------------------------------------------------------------------
  // Test that each CSV has correct headers
  // -------------------------------------------------------------------------

  it('claims.csv has correct headers', async () => {
    const deps = createExportDeps();
    const userId = crypto.randomUUID();

    const zipBuffer = await generateFullPortabilityExport(deps, userId);
    const zip = new AdmZip.default(zipBuffer);
    const claimsCsv = zip.readAsText('claims.csv');

    expect(claimsCsv).toContain('claim_id');
    expect(claimsCsv).toContain('service_date');
    expect(claimsCsv).toContain('health_service_code');
    expect(claimsCsv).toContain('amount');
    expect(claimsCsv).toContain('status');
  });

  it('wcb_claims.csv has correct headers', async () => {
    const deps = createExportDeps();
    const userId = crypto.randomUUID();

    const zipBuffer = await generateFullPortabilityExport(deps, userId);
    const zip = new AdmZip.default(zipBuffer);
    const wcbCsv = zip.readAsText('wcb_claims.csv');

    expect(wcbCsv).toContain('claim_id');
    expect(wcbCsv).toContain('service_date');
    expect(wcbCsv).toContain('form_type');
    expect(wcbCsv).toContain('status');
    expect(wcbCsv).toContain('amount');
  });

  it('patients.csv has correct headers', async () => {
    const deps = createExportDeps();
    const userId = crypto.randomUUID();

    const zipBuffer = await generateFullPortabilityExport(deps, userId);
    const zip = new AdmZip.default(zipBuffer);
    const patientsCsv = zip.readAsText('patients.csv');

    expect(patientsCsv).toContain('patient_id');
    expect(patientsCsv).toContain('first_name');
    expect(patientsCsv).toContain('last_name');
    expect(patientsCsv).toContain('date_of_birth');
    expect(patientsCsv).toContain('phn');
  });

  it('assessments.csv has correct headers', async () => {
    const deps = createExportDeps();
    const userId = crypto.randomUUID();

    const zipBuffer = await generateFullPortabilityExport(deps, userId);
    const zip = new AdmZip.default(zipBuffer);
    const csv = zip.readAsText('assessments.csv');

    expect(csv).toContain('assessment_id');
    expect(csv).toContain('patient_id');
    expect(csv).toContain('assessment_date');
    expect(csv).toContain('type');
    expect(csv).toContain('status');
  });

  it('analytics.csv has correct headers', async () => {
    const deps = createExportDeps();
    const userId = crypto.randomUUID();

    const zipBuffer = await generateFullPortabilityExport(deps, userId);
    const zip = new AdmZip.default(zipBuffer);
    const csv = zip.readAsText('analytics.csv');

    expect(csv).toContain('metric');
    expect(csv).toContain('period');
    expect(csv).toContain('value');
    expect(csv).toContain('unit');
  });

  it('intelligence.csv has correct headers', async () => {
    const deps = createExportDeps();
    const userId = crypto.randomUUID();

    const zipBuffer = await generateFullPortabilityExport(deps, userId);
    const zip = new AdmZip.default(zipBuffer);
    const csv = zip.readAsText('intelligence.csv');

    expect(csv).toContain('insight_id');
    expect(csv).toContain('generated_at');
    expect(csv).toContain('category');
    expect(csv).toContain('recommendation');
    expect(csv).toContain('confidence');
  });

  // -------------------------------------------------------------------------
  // Test physician scoping (different userId returns different data)
  // -------------------------------------------------------------------------

  it('different userId calls generate separate exports', async () => {
    const deps = createExportDeps();
    const userId1 = crypto.randomUUID();
    const userId2 = crypto.randomUUID();

    const buffer1 = await generateFullPortabilityExport(deps, userId1);
    const buffer2 = await generateFullPortabilityExport(deps, userId2);

    // Both should return valid buffers (stubs return same headers for now)
    expect(buffer1).toBeInstanceOf(Buffer);
    expect(buffer2).toBeInstanceOf(Buffer);
    expect(buffer1.length).toBeGreaterThan(0);
    expect(buffer2.length).toBeGreaterThan(0);

    // Both ZIPs should contain 6 files
    const zip1 = new AdmZip.default(buffer1);
    const zip2 = new AdmZip.default(buffer2);
    expect(zip1.getEntries()).toHaveLength(6);
    expect(zip2.getEntries()).toHaveLength(6);
  });

  // -------------------------------------------------------------------------
  // Test that cancelled-status users can still access export
  // -------------------------------------------------------------------------

  it('cancelled-status users can still generate export', async () => {
    const deps = createExportDeps();
    // Simulate a cancelled user — the export service does not check subscription status;
    // that is enforced at the route/middleware level via FeatureAccessMatrix.
    // The FeatureAccessMatrix grants DATA_EXPORT to CANCELLED users.
    // Here we simply verify the export function works for any userId.
    const cancelledUserId = crypto.randomUUID();

    const result = await generateFullPortabilityExport(deps, cancelledUserId);

    expect(result).toBeInstanceOf(Buffer);
    expect(result.length).toBeGreaterThan(0);

    const zip = new AdmZip.default(result);
    expect(zip.getEntries()).toHaveLength(6);
  });

  // -------------------------------------------------------------------------
  // Individual CSV stub functions
  // -------------------------------------------------------------------------

  describe('individual CSV stubs', () => {
    it('generateClaimsCsv returns header-only CSV', async () => {
      const db = createMockDb();
      const csv = await generateClaimsCsv(db, crypto.randomUUID());
      expect(csv).toContain('claim_id');
      expect(csv.trim().split('\n')).toHaveLength(1);
    });

    it('exportWcbClaimsCsv returns header-only CSV', async () => {
      const db = createMockDb();
      const csv = await exportWcbClaimsCsv(db, crypto.randomUUID());
      expect(csv).toContain('claim_id');
      expect(csv).toContain('form_type');
      expect(csv.trim().split('\n')).toHaveLength(1);
    });

    it('exportAssessmentsCsv returns header-only CSV', async () => {
      const db = createMockDb();
      const csv = await exportAssessmentsCsv(db, crypto.randomUUID());
      expect(csv).toContain('assessment_id');
      expect(csv.trim().split('\n')).toHaveLength(1);
    });

    it('exportAnalyticsCsv returns header-only CSV', async () => {
      const db = createMockDb();
      const csv = await exportAnalyticsCsv(db, crypto.randomUUID());
      expect(csv).toContain('metric');
      expect(csv.trim().split('\n')).toHaveLength(1);
    });

    it('exportIntelligenceCsv returns header-only CSV', async () => {
      const db = createMockDb();
      const csv = await exportIntelligenceCsv(db, crypto.randomUUID());
      expect(csv).toContain('insight_id');
      expect(csv.trim().split('\n')).toHaveLength(1);
    });
  });
});

// ===========================================================================
// IMA-051: Full HI Export — Service Tests
// ===========================================================================

describe('IMA-051: Full Health Information Export', () => {
  const PROVIDER_ID = crypto.randomUUID();
  const CTX: ExportAuthContext = {
    userId: PROVIDER_ID,
    providerId: PROVIDER_ID,
  };

  function createEmptyHi(): CompleteHealthInformation {
    return {
      patients: [],
      claims: [],
      claimAuditHistory: [],
      shifts: [],
      claimExports: [],
      ahcipClaimDetails: [],
      ahcipBatches: [],
      wcbClaimDetails: [],
      wcbBatches: [],
      wcbRemittanceImports: [],
      provider: null,
      businessArrangements: [],
      practiceLocations: [],
      wcbConfigurations: [],
      delegateRelationships: [],
      submissionPreferences: [],
      hlinkConfigurations: [],
      pcpcmEnrolments: [],
      pcpcmPayments: [],
      pcpcmPanelEstimates: [],
      analyticsCache: [],
      generatedReports: [],
      reportSubscriptions: [],
      aiProviderLearning: [],
      aiSuggestionEvents: [],
      edShifts: [],
      favouriteCodes: [],
      subscription: null,
      imaAmendmentResponses: [],
      auditLog: [],
    };
  }

  function createHiWithData(): CompleteHealthInformation {
    return {
      ...createEmptyHi(),
      patients: [
        { patientId: crypto.randomUUID(), firstName: 'Jane', lastName: 'Doe', dob: '1990-01-01', phn: '123456789' },
        { patientId: crypto.randomUUID(), firstName: 'John', lastName: 'Smith', dob: '1985-06-15', phn: '987654321' },
      ],
      claims: [
        { claimId: crypto.randomUUID(), serviceDate: '2026-01-01', code: '03.03A', amount: '50.00', status: 'PAID' },
      ],
      provider: { providerId: PROVIDER_ID, firstName: 'Dr', lastName: 'Test', email: 'dr@test.ca' },
      subscription: { subscriptionId: crypto.randomUUID(), status: 'ACTIVE', plan: 'STANDARD_MONTHLY' },
    };
  }

  let uploadedBuffers: Map<string, Buffer>;
  let presignedUrls: Map<string, string>;
  let reportStore: Array<{ reportId: string; providerId: string; reportType: string; format: string; filePath: string; fileSizeBytes: number; downloadLinkExpiresAt: Date; status: string }>;
  let auditLogs: Array<{ action: string; resourceType: string; resourceId: string; actorType: string; metadata?: Record<string, unknown> }>;
  let emittedEvents: Array<{ event: string; data: Record<string, unknown> }>;

  function createFullHiExportDeps(hiData?: CompleteHealthInformation): FullHiExportDeps {
    uploadedBuffers = new Map();
    presignedUrls = new Map();
    reportStore = [];
    auditLogs = [];
    emittedEvents = [];

    return {
      exportRepo: {
        getCompleteHealthInformation: vi.fn().mockResolvedValue(hiData ?? createEmptyHi()),
      } as any,
      reportRepo: {
        createReport: vi.fn().mockImplementation((data) => {
          const report = { reportId: crypto.randomUUID(), ...data };
          reportStore.push(report);
          return Promise.resolve(report);
        }),
      },
      objectStorage: {
        uploadBuffer: vi.fn().mockImplementation((key: string, buffer: Buffer) => {
          uploadedBuffers.set(key, buffer);
          return Promise.resolve();
        }),
        getPresignedUrl: vi.fn().mockImplementation((key: string, _expiresIn: number) => {
          const url = `https://meritum-files.tor1.digitaloceanspaces.com/${key}?sig=mock`;
          presignedUrls.set(key, url);
          return Promise.resolve(url);
        }),
      },
      auditLogger: {
        log: vi.fn().mockImplementation((entry) => {
          auditLogs.push(entry);
          return Promise.resolve();
        }),
      },
      eventEmitter: {
        emit: vi.fn().mockImplementation((event: string, data: Record<string, unknown>) => {
          emittedEvents.push({ event, data });
        }),
      },
    };
  }

  // -------------------------------------------------------------------------
  // Core functionality
  // -------------------------------------------------------------------------

  it('returns reportId, downloadUrl, and expiresAt', async () => {
    const deps = createFullHiExportDeps();
    const result = await generateFullHiExport(deps, CTX, 'csv');

    expect(result.reportId).toBeDefined();
    expect(typeof result.reportId).toBe('string');
    expect(result.downloadUrl).toBeDefined();
    expect(result.downloadUrl).toContain('https://');
    expect(result.expiresAt).toBeDefined();
    // expiresAt should be ~72h from now
    const expiresAt = new Date(result.expiresAt);
    const now = Date.now();
    const diffHours = (expiresAt.getTime() - now) / (1000 * 60 * 60);
    expect(diffHours).toBeGreaterThan(71);
    expect(diffHours).toBeLessThan(73);
  });

  it('export ZIP contains manifest.json with entity counts', async () => {
    const hiData = createHiWithData();
    const deps = createFullHiExportDeps(hiData);
    await generateFullHiExport(deps, CTX, 'csv');

    // Find the uploaded buffer
    expect(uploadedBuffers.size).toBe(1);
    const zipBuffer = [...uploadedBuffers.values()][0];
    const zip = new AdmZip.default(zipBuffer);

    // Check manifest exists
    const manifestEntry = zip.getEntry('manifest.json');
    expect(manifestEntry).toBeDefined();

    const manifest = JSON.parse(zip.readAsText('manifest.json'));
    expect(manifest.export_date).toBeDefined();
    expect(manifest.provider_id).toBe(PROVIDER_ID);
    expect(manifest.format).toBe('csv');
    expect(manifest.schema_version).toBe('1.0.0');
    expect(manifest.entity_counts).toBeDefined();
    expect(manifest.entity_counts.patients).toBe(2);
    expect(manifest.entity_counts.claims).toBe(1);
    expect(manifest.entity_counts.provider).toBe(1);
    expect(manifest.entity_counts.subscription).toBe(1);
  });

  it('export ZIP contains entity CSV files for non-empty entities', async () => {
    const hiData = createHiWithData();
    const deps = createFullHiExportDeps(hiData);
    await generateFullHiExport(deps, CTX, 'csv');

    const zipBuffer = [...uploadedBuffers.values()][0];
    const zip = new AdmZip.default(zipBuffer);
    const entryNames = zip.getEntries().map((e) => e.entryName);

    // Should include manifest + entity files for non-empty entities
    expect(entryNames).toContain('manifest.json');
    expect(entryNames).toContain('patients.csv');
    expect(entryNames).toContain('claims.csv');
    expect(entryNames).toContain('provider.csv');
    expect(entryNames).toContain('subscription.csv');
  });

  it('supports JSON format', async () => {
    const hiData = createHiWithData();
    const deps = createFullHiExportDeps(hiData);
    await generateFullHiExport(deps, CTX, 'json');

    const zipBuffer = [...uploadedBuffers.values()][0];
    const zip = new AdmZip.default(zipBuffer);
    const entryNames = zip.getEntries().map((e) => e.entryName);

    expect(entryNames).toContain('manifest.json');
    expect(entryNames).toContain('patients.json');
    expect(entryNames).toContain('claims.json');

    // Verify JSON content is valid
    const patientsJson = zip.readAsText('patients.json');
    const parsed = JSON.parse(patientsJson);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed).toHaveLength(2);
  });

  it('empty dataset produces ZIP with only manifest', async () => {
    const deps = createFullHiExportDeps(createEmptyHi());
    await generateFullHiExport(deps, CTX, 'csv');

    const zipBuffer = [...uploadedBuffers.values()][0];
    const zip = new AdmZip.default(zipBuffer);
    const entryNames = zip.getEntries().map((e) => e.entryName);

    // Only manifest should be present when all entities are empty
    expect(entryNames).toEqual(['manifest.json']);
  });

  // -------------------------------------------------------------------------
  // Object storage
  // -------------------------------------------------------------------------

  it('uploads to correct object storage path', async () => {
    const deps = createFullHiExportDeps();
    await generateFullHiExport(deps, CTX, 'csv');

    expect(uploadedBuffers.size).toBe(1);
    const key = [...uploadedBuffers.keys()][0];
    expect(key).toMatch(new RegExp(`^exports/${PROVIDER_ID}/.*\\.zip$`));
  });

  it('presigned URL expires after 72 hours', async () => {
    const deps = createFullHiExportDeps();
    const result = await generateFullHiExport(deps, CTX, 'csv');

    const expiresAt = new Date(result.expiresAt);
    const expectedMinimum = new Date(Date.now() + 71 * 60 * 60 * 1000);
    const expectedMaximum = new Date(Date.now() + 73 * 60 * 60 * 1000);

    expect(expiresAt.getTime()).toBeGreaterThanOrEqual(expectedMinimum.getTime());
    expect(expiresAt.getTime()).toBeLessThanOrEqual(expectedMaximum.getTime());
  });

  // -------------------------------------------------------------------------
  // Report record
  // -------------------------------------------------------------------------

  it('creates a generatedReports record with type FULL_DATA_PORTABILITY', async () => {
    const deps = createFullHiExportDeps();
    await generateFullHiExport(deps, CTX, 'csv');

    expect(reportStore).toHaveLength(1);
    expect(reportStore[0].providerId).toBe(PROVIDER_ID);
    expect(reportStore[0].reportType).toBe('FULL_DATA_PORTABILITY');
    expect(reportStore[0].format).toBe('csv');
    expect(reportStore[0].status).toBe('ready');
    expect(reportStore[0].fileSizeBytes).toBeGreaterThan(0);
  });

  // -------------------------------------------------------------------------
  // Audit logging
  // -------------------------------------------------------------------------

  it('audit log records export request and completion', async () => {
    const deps = createFullHiExportDeps();
    await generateFullHiExport(deps, CTX, 'csv');

    expect(auditLogs).toHaveLength(2);

    const requestLog = auditLogs.find((l) => l.action === 'export.full_hi_requested');
    expect(requestLog).toBeDefined();
    expect(requestLog!.resourceType).toBe('export');
    expect(requestLog!.actorType).toBe('physician');

    const readyLog = auditLogs.find((l) => l.action === 'export.full_hi_ready');
    expect(readyLog).toBeDefined();
    expect(readyLog!.resourceType).toBe('export');
  });

  it('audit log entries do not contain PHI', async () => {
    const hiData = createHiWithData();
    const deps = createFullHiExportDeps(hiData);
    await generateFullHiExport(deps, CTX, 'csv');

    const logStr = JSON.stringify(auditLogs);
    // Should not contain patient names or PHNs
    expect(logStr).not.toContain('Jane');
    expect(logStr).not.toContain('Doe');
    expect(logStr).not.toContain('123456789');
    expect(logStr).not.toContain('987654321');
  });

  // -------------------------------------------------------------------------
  // Event emission
  // -------------------------------------------------------------------------

  it('emits FULL_HI_EXPORT_READY notification', async () => {
    const deps = createFullHiExportDeps();
    const result = await generateFullHiExport(deps, CTX, 'csv');

    const event = emittedEvents.find((e) => e.event === 'FULL_HI_EXPORT_READY');
    expect(event).toBeDefined();
    expect(event!.data.reportId).toBe(result.reportId);
    expect(event!.data.providerId).toBe(PROVIDER_ID);
    expect(event!.data.format).toBe('csv');
    expect(event!.data.downloadUrl).toBeDefined();
    expect(event!.data.expiresAt).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // Physician scoping
  // -------------------------------------------------------------------------

  it('calls exportRepo with authenticated providerId', async () => {
    const deps = createFullHiExportDeps();
    await generateFullHiExport(deps, CTX, 'csv');

    expect(deps.exportRepo.getCompleteHealthInformation).toHaveBeenCalledWith(PROVIDER_ID);
  });

  // -------------------------------------------------------------------------
  // CANCELLED subscription state — feature access preserved
  // -------------------------------------------------------------------------

  it('export accessible regardless of subscription status (service layer)', async () => {
    // The service layer does not check subscription status —
    // that is enforced at the route level via FeatureAccessMatrix.
    // DATA_EXPORT is granted to CANCELLED users in FeatureAccessMatrix.
    const cancelledProviderId = crypto.randomUUID();
    const cancelledCtx: ExportAuthContext = {
      userId: cancelledProviderId,
      providerId: cancelledProviderId,
    };

    const deps = createFullHiExportDeps();
    const result = await generateFullHiExport(deps, cancelledCtx, 'csv');

    expect(result.reportId).toBeDefined();
    expect(result.downloadUrl).toBeDefined();
  });
});
