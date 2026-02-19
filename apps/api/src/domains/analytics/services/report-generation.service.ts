// ============================================================================
// Domain 8: Report Generation Service
// Generates accountant exports (CSV/PDF), data portability ZIP, and dispatches
// report processing by type. All queries scoped to providerId.
// ============================================================================

import {
  ReportType,
  ReportFormat,
} from '@meritum/shared/constants/analytics.constants.js';
import type { GeneratedReportsRepository } from '../repos/generated-reports.repo.js';
import type { DashboardQueryRepository } from '../repos/dashboard-query.repo.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Claim row from the accountant CSV/PDF queries. */
export interface AccountantClaimRow {
  dateOfService: string;
  hscCode: string;
  modifiers: string;
  submittedFee: string;
  assessedFee: string;
  paymentDate: string;
  baNumber: string;
  location: string;
  claimType: string;
}

/** Provider profile for PDF headers. */
export interface ProviderProfile {
  physicianName: string;
  baNumbers: string[];
}

/** Revenue summary for PDF summary report. */
export interface RevenueSummary {
  totalRevenue: string;
  revenueByBa: Array<{ baNumber: string; revenue: string }>;
  revenueByLocation: Array<{ locationName: string; revenue: string }>;
  ahcipRevenue: string;
  wcbRevenue: string;
  claimCount: number;
  rrnpPremiumTotal: string;
  adjustments: string;
  writtenOff: string;
}

/** Data portability CSV contents. */
export interface DataPortabilityData {
  claims: string;
  patients: string;
  auditHistory: string;
  aiSuggestions: string;
  batches: string;
  providerProfile: string;
}

/** Abstraction for file storage (local FS or object storage). */
export interface FileStorage {
  writeFile(filePath: string, data: Buffer | string): Promise<void>;
  getFileSize(filePath: string): Promise<number>;
}

/** Abstraction for PDF generation. */
export interface PdfGenerator {
  generateSummaryPdf(
    profile: ProviderProfile,
    period: { start: string; end: string },
    summary: RevenueSummary,
  ): Promise<Buffer>;
  generateDetailPdf(
    profile: ProviderProfile,
    period: { start: string; end: string },
    rows: AccountantClaimRow[],
  ): Promise<Buffer>;
}

/** Abstraction for ZIP archive creation. */
export interface ZipArchiver {
  createZip(
    entries: Array<{ name: string; content: string | Buffer }>,
    password?: string,
  ): Promise<Buffer>;
}

/** Data access functions injected into the service. */
export interface ReportDataAccess {
  /** Query paid claims for accountant export. Scoped to providerId. */
  getPaidClaims(
    providerId: string,
    periodStart: string,
    periodEnd: string,
  ): Promise<AccountantClaimRow[]>;

  /** Get provider profile for PDF headers. Scoped to providerId. */
  getProviderProfile(providerId: string): Promise<ProviderProfile>;

  /** Get revenue summary for PDF summary. Scoped to providerId. */
  getRevenueSummary(
    providerId: string,
    periodStart: string,
    periodEnd: string,
  ): Promise<RevenueSummary>;

  /** Get all data for portability export. Scoped to providerId. */
  getPortabilityData(providerId: string): Promise<DataPortabilityData>;
}

interface ReportGenerationDeps {
  reportsRepo: GeneratedReportsRepository;
  dataAccess: ReportDataAccess;
  fileStorage: FileStorage;
  pdfGenerator: PdfGenerator;
  zipArchiver: ZipArchiver;
  getStoragePath: (reportId: string, format: string) => string;
}

// ---------------------------------------------------------------------------
// CSV Helpers
// ---------------------------------------------------------------------------

const ACCOUNTANT_CSV_HEADERS = [
  'date_of_service',
  'hsc_code',
  'modifiers',
  'submitted_fee',
  'assessed_fee',
  'payment_date',
  'ba_number',
  'location',
  'claim_type',
];

function escapeCsvField(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function claimRowToCsvLine(row: AccountantClaimRow): string {
  return [
    row.dateOfService,
    row.hscCode,
    row.modifiers,
    row.submittedFee,
    row.assessedFee,
    row.paymentDate,
    row.baNumber,
    row.location,
    row.claimType,
  ]
    .map(escapeCsvField)
    .join(',');
}

export function buildAccountantCsv(rows: AccountantClaimRow[]): string {
  const header = ACCOUNTANT_CSV_HEADERS.join(',');
  const lines = rows.map(claimRowToCsvLine);
  return [header, ...lines].join('\n');
}

// ---------------------------------------------------------------------------
// Data Portability README
// ---------------------------------------------------------------------------

const DATA_PORTABILITY_README = `Meritum Health Technologies — Data Portability Export
=====================================================

This archive contains a complete export of your data from Meritum.

Files included:
- claims.csv: All claims across all states with complete field data
- patients.csv: Complete patient registry
- audit_history.csv: All claim and entity state change records
- ai_suggestions.csv: All AI Coach suggestions with acceptance status
- batches.csv: AHCIP and WCB batch submission records
- provider_profile.csv: BA numbers, practice locations, WCB configuration

Data format:
- All files are UTF-8 encoded CSV with headers
- Dates are in ISO 8601 format (YYYY-MM-DD)
- Monetary values are decimal strings with 2 decimal places
- IDs are UUID v4 format

This export was generated per your request under Alberta's Health Information Act.
For questions, contact support@meritum.ca.
`;

// ---------------------------------------------------------------------------
// Service Factory
// ---------------------------------------------------------------------------

export function createReportGenerationService(deps: ReportGenerationDeps) {
  const {
    reportsRepo,
    dataAccess,
    fileStorage,
    pdfGenerator,
    zipArchiver,
    getStoragePath,
  } = deps;

  async function generateAccountantCsv(
    reportId: string,
    providerId: string,
    periodStart: string,
    periodEnd: string,
  ): Promise<void> {
    const rows = await dataAccess.getPaidClaims(
      providerId,
      periodStart,
      periodEnd,
    );
    const csv = buildAccountantCsv(rows);
    const filePath = getStoragePath(reportId, 'csv');

    await fileStorage.writeFile(filePath, csv);
    const fileSize = await fileStorage.getFileSize(filePath);

    await reportsRepo.updateStatus(
      reportId,
      providerId,
      'ready',
      filePath,
      fileSize,
    );
  }

  async function generateAccountantPdfSummary(
    reportId: string,
    providerId: string,
    periodStart: string,
    periodEnd: string,
  ): Promise<void> {
    const [profile, summary] = await Promise.all([
      dataAccess.getProviderProfile(providerId),
      dataAccess.getRevenueSummary(providerId, periodStart, periodEnd),
    ]);

    const pdfBuffer = await pdfGenerator.generateSummaryPdf(
      profile,
      { start: periodStart, end: periodEnd },
      summary,
    );

    const filePath = getStoragePath(reportId, 'pdf');
    await fileStorage.writeFile(filePath, pdfBuffer);
    const fileSize = await fileStorage.getFileSize(filePath);

    await reportsRepo.updateStatus(
      reportId,
      providerId,
      'ready',
      filePath,
      fileSize,
    );
  }

  async function generateAccountantPdfDetail(
    reportId: string,
    providerId: string,
    periodStart: string,
    periodEnd: string,
  ): Promise<void> {
    const [profile, rows] = await Promise.all([
      dataAccess.getProviderProfile(providerId),
      dataAccess.getPaidClaims(providerId, periodStart, periodEnd),
    ]);

    const pdfBuffer = await pdfGenerator.generateDetailPdf(
      profile,
      { start: periodStart, end: periodEnd },
      rows,
    );

    const filePath = getStoragePath(reportId, 'pdf');
    await fileStorage.writeFile(filePath, pdfBuffer);
    const fileSize = await fileStorage.getFileSize(filePath);

    await reportsRepo.updateStatus(
      reportId,
      providerId,
      'ready',
      filePath,
      fileSize,
    );
  }

  async function generateDataPortabilityExport(
    reportId: string,
    providerId: string,
    password?: string,
  ): Promise<void> {
    const portabilityData = await dataAccess.getPortabilityData(providerId);

    const entries = [
      { name: 'claims.csv', content: portabilityData.claims },
      { name: 'patients.csv', content: portabilityData.patients },
      { name: 'audit_history.csv', content: portabilityData.auditHistory },
      { name: 'ai_suggestions.csv', content: portabilityData.aiSuggestions },
      { name: 'batches.csv', content: portabilityData.batches },
      {
        name: 'provider_profile.csv',
        content: portabilityData.providerProfile,
      },
      { name: 'README.txt', content: DATA_PORTABILITY_README },
    ];

    const zipBuffer = await zipArchiver.createZip(entries, password);

    const filePath = getStoragePath(reportId, 'zip');
    await fileStorage.writeFile(filePath, zipBuffer);
    const fileSize = await fileStorage.getFileSize(filePath);

    await reportsRepo.updateStatus(
      reportId,
      providerId,
      'ready',
      filePath,
      fileSize,
    );
  }

  async function processReport(
    reportId: string,
    providerId: string,
  ): Promise<void> {
    // Fetch the report record (scoped to provider)
    const report = await reportsRepo.getById(reportId, providerId);
    if (!report) {
      return;
    }

    // Set status to 'generating'
    await reportsRepo.updateStatus(reportId, providerId, 'generating');

    try {
      switch (report.reportType) {
        case ReportType.ACCOUNTANT_SUMMARY: {
          if (report.format === ReportFormat.CSV) {
            await generateAccountantCsv(
              reportId,
              providerId,
              report.periodStart!,
              report.periodEnd!,
            );
          } else {
            await generateAccountantPdfSummary(
              reportId,
              providerId,
              report.periodStart!,
              report.periodEnd!,
            );
          }
          break;
        }

        case ReportType.ACCOUNTANT_DETAIL: {
          if (report.format === ReportFormat.CSV) {
            await generateAccountantCsv(
              reportId,
              providerId,
              report.periodStart!,
              report.periodEnd!,
            );
          } else {
            await generateAccountantPdfDetail(
              reportId,
              providerId,
              report.periodStart!,
              report.periodEnd!,
            );
          }
          break;
        }

        case ReportType.DATA_PORTABILITY: {
          // Password is not stored in the report record — it must be passed
          // through a separate channel. For processReport dispatch, we generate
          // without password (password-protected exports use the direct method).
          await generateDataPortabilityExport(reportId, providerId);
          break;
        }

        default: {
          throw new Error(`Unsupported report type: ${report.reportType}`);
        }
      }
    } catch (error) {
      // On failure: set status to 'failed' with a generic error message
      // (never expose internal details or PHI in error messages)
      await reportsRepo.updateStatus(
        reportId,
        providerId,
        'failed',
        undefined,
        undefined,
        'Report generation failed. Please try again or contact support.',
      );
    }
  }

  return {
    generateAccountantCsv,
    generateAccountantPdfSummary,
    generateAccountantPdfDetail,
    generateDataPortabilityExport,
    processReport,
  };
}

export type ReportGenerationService = ReturnType<
  typeof createReportGenerationService
>;
