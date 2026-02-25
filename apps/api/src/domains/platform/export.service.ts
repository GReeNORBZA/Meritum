// ============================================================================
// D19-010/011/012: Data Portability Export Service
// IMA-051: Complete HI Export — service + handler + route
// ============================================================================

import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as archiver from 'archiver';
import { PassThrough } from 'node:stream';
import {
  type ExportRepository,
  type CompleteHealthInformation,
} from './export.repository.js';
import { type AuditLogger, type PlatformEventEmitter } from './platform.service.js';

// ---------------------------------------------------------------------------
// CSV generator stubs (D19-010/011/012)
// ---------------------------------------------------------------------------

/**
 * D19-010: Export AHCIP claims as CSV.
 * Stub implementation — will be connected when claims domain is available.
 */
export async function generateClaimsCsv(
  db: NodePgDatabase,
  providerId: string,
): Promise<string> {
  // TODO: Implement when claims domain is available
  return 'claim_id,service_date,health_service_code,amount,status\n';
}

/**
 * D19-011: Export WCB claims as CSV.
 * Stub implementation — WCB domain may not exist yet.
 */
export async function exportWcbClaimsCsv(
  db: NodePgDatabase,
  providerId: string,
): Promise<string> {
  // TODO: Implement when WCB domain is available
  return 'claim_id,service_date,form_type,status,amount\n';
}

/**
 * D19-010: Export patients as CSV.
 * Stub implementation — will be connected when patients domain is available.
 */
export async function generatePatientsCsv(
  db: NodePgDatabase,
  providerId: string,
): Promise<string> {
  // TODO: Implement when patients domain is available
  return 'patient_id,first_name,last_name,date_of_birth,phn\n';
}

/**
 * D19-012: Export assessments as CSV.
 * Stub implementation.
 */
export async function exportAssessmentsCsv(
  db: NodePgDatabase,
  providerId: string,
): Promise<string> {
  // TODO: Implement when assessments domain is available
  return 'assessment_id,patient_id,assessment_date,type,status\n';
}

/**
 * D19-012: Export analytics summary as CSV.
 * Stub implementation.
 */
export async function exportAnalyticsCsv(
  db: NodePgDatabase,
  providerId: string,
): Promise<string> {
  // TODO: Implement when analytics domain is available
  return 'metric,period,value,unit\n';
}

/**
 * D19-012: Export AI coaching/intelligence data as CSV.
 * Stub implementation.
 */
export async function exportIntelligenceCsv(
  db: NodePgDatabase,
  providerId: string,
): Promise<string> {
  // TODO: Implement when intelligence domain is available
  return 'insight_id,generated_at,category,recommendation,confidence\n';
}

// ---------------------------------------------------------------------------
// D19-010: ZIP orchestration
// ---------------------------------------------------------------------------

export interface ExportDeps {
  db: NodePgDatabase;
}

/**
 * Generate a full data portability export for a physician.
 *
 * Bundles 6 CSV data types into a ZIP:
 *   - claims.csv (AHCIP claims)
 *   - wcb_claims.csv (WCB claims)
 *   - patients.csv (patients)
 *   - assessments.csv (assessments)
 *   - analytics.csv (summary analytics)
 *   - intelligence.csv (AI coaching data)
 *
 * Returns a Buffer containing the ZIP file.
 */
export async function generateFullPortabilityExport(
  deps: ExportDeps,
  userId: string,
): Promise<Buffer> {
  // Generate all CSV data in parallel
  const [
    claimsCsv,
    wcbClaimsCsv,
    patientsCsv,
    assessmentsCsv,
    analyticsCsv,
    intelligenceCsv,
  ] = await Promise.all([
    generateClaimsCsv(deps.db, userId),
    exportWcbClaimsCsv(deps.db, userId),
    generatePatientsCsv(deps.db, userId),
    exportAssessmentsCsv(deps.db, userId),
    exportAnalyticsCsv(deps.db, userId),
    exportIntelligenceCsv(deps.db, userId),
  ]);

  // Create ZIP archive
  const archive = archiver.create('zip', { zlib: { level: 9 } });
  const passThrough = new PassThrough();
  const chunks: Buffer[] = [];

  // Collect chunks from the stream
  const bufferPromise = new Promise<Buffer>((resolve, reject) => {
    passThrough.on('data', (chunk: Buffer) => chunks.push(chunk));
    passThrough.on('end', () => resolve(Buffer.concat(chunks)));
    passThrough.on('error', reject);
    archive.on('error', reject);
  });

  archive.pipe(passThrough);

  // Add CSV files to the archive
  archive.append(claimsCsv, { name: 'claims.csv' });
  archive.append(wcbClaimsCsv, { name: 'wcb_claims.csv' });
  archive.append(patientsCsv, { name: 'patients.csv' });
  archive.append(assessmentsCsv, { name: 'assessments.csv' });
  archive.append(analyticsCsv, { name: 'analytics.csv' });
  archive.append(intelligenceCsv, { name: 'intelligence.csv' });

  await archive.finalize();

  return bufferPromise;
}

// ---------------------------------------------------------------------------
// IMA-051: Full Health Information Export
// ---------------------------------------------------------------------------

/**
 * Presigned URL expiry for full HI exports: 72 hours.
 */
const FULL_EXPORT_URL_EXPIRY_HOURS = 72;

/**
 * Schema version for the manifest file.
 */
const EXPORT_SCHEMA_VERSION = '1.0.0';

/**
 * Dependencies for the full HI export service function.
 */
export interface FullHiExportDeps {
  exportRepo: ExportRepository;
  reportRepo: {
    createReport(data: {
      providerId: string;
      reportType: string;
      format: string;
      filePath: string;
      fileSizeBytes: number;
      downloadLinkExpiresAt: Date;
      status: string;
    }): Promise<{ reportId: string }>;
  };
  objectStorage: {
    uploadBuffer(key: string, buffer: Buffer, contentType: string): Promise<void>;
    getPresignedUrl(key: string, expiresInSeconds: number): Promise<string>;
  };
  auditLogger?: AuditLogger;
  eventEmitter?: PlatformEventEmitter;
}

/**
 * Auth context for the export request.
 */
export interface ExportAuthContext {
  userId: string;
  providerId: string;
}

/**
 * Result of a full HI export.
 */
export interface FullHiExportResult {
  reportId: string;
  downloadUrl: string;
  expiresAt: string;
}

/**
 * Convert an array of objects to CSV format.
 * Handles null/undefined values gracefully.
 */
function toCsv(rows: unknown[]): string {
  if (rows.length === 0) return '';
  const firstRow = rows[0] as Record<string, unknown>;
  const headers = Object.keys(firstRow);
  const headerLine = headers.join(',');
  const dataLines = rows.map((row) => {
    const r = row as Record<string, unknown>;
    return headers
      .map((h) => {
        const val = r[h];
        if (val === null || val === undefined) return '';
        const str = String(val);
        // Escape CSV values that contain commas, quotes, or newlines
        if (str.includes(',') || str.includes('"') || str.includes('\n')) {
          return `"${str.replace(/"/g, '""')}"`;
        }
        return str;
      })
      .join(',');
  });
  return [headerLine, ...dataLines].join('\n') + '\n';
}

/**
 * Convert an array of objects to JSON format (pretty-printed).
 */
function toJson(rows: unknown[]): string {
  return JSON.stringify(rows, null, 2);
}

/**
 * Build entity counts from the CompleteHealthInformation object.
 */
function buildEntityCounts(hi: CompleteHealthInformation): Record<string, number> {
  return {
    patients: hi.patients.length,
    claims: hi.claims.length,
    claimAuditHistory: hi.claimAuditHistory.length,
    shifts: hi.shifts.length,
    claimExports: hi.claimExports.length,
    ahcipClaimDetails: hi.ahcipClaimDetails.length,
    ahcipBatches: hi.ahcipBatches.length,
    wcbClaimDetails: hi.wcbClaimDetails.length,
    wcbBatches: hi.wcbBatches.length,
    wcbRemittanceImports: hi.wcbRemittanceImports.length,
    provider: hi.provider ? 1 : 0,
    businessArrangements: hi.businessArrangements.length,
    practiceLocations: hi.practiceLocations.length,
    wcbConfigurations: hi.wcbConfigurations.length,
    delegateRelationships: hi.delegateRelationships.length,
    submissionPreferences: hi.submissionPreferences.length,
    hlinkConfigurations: hi.hlinkConfigurations.length,
    pcpcmEnrolments: hi.pcpcmEnrolments.length,
    pcpcmPayments: hi.pcpcmPayments.length,
    pcpcmPanelEstimates: hi.pcpcmPanelEstimates.length,
    analyticsCache: hi.analyticsCache.length,
    generatedReports: hi.generatedReports.length,
    reportSubscriptions: hi.reportSubscriptions.length,
    aiProviderLearning: hi.aiProviderLearning.length,
    aiSuggestionEvents: hi.aiSuggestionEvents.length,
    edShifts: hi.edShifts.length,
    favouriteCodes: hi.favouriteCodes.length,
    subscription: hi.subscription ? 1 : 0,
    imaAmendmentResponses: hi.imaAmendmentResponses.length,
    auditLog: hi.auditLog.length,
  };
}

/**
 * Serialise a single entity type to the requested format.
 */
function serialiseEntity(
  rows: unknown[],
  format: 'csv' | 'json',
): string {
  if (rows.length === 0) {
    return format === 'csv' ? '' : '[]';
  }
  return format === 'csv' ? toCsv(rows) : toJson(rows);
}

/**
 * IMA-051: Generate a complete Health Information export for a physician.
 *
 * 1. Retrieve ALL HI via the export repository.
 * 2. Serialise each entity type to the requested format (CSV or JSON).
 * 3. Bundle into a ZIP with manifest.json.
 * 4. Upload to DO Spaces.
 * 5. Generate presigned download URL (72h expiry).
 * 6. Create generatedReports record with type FULL_DATA_PORTABILITY.
 * 7. Emit audit events and notification.
 * 8. Return { reportId, downloadUrl, expiresAt }.
 */
export async function generateFullHiExport(
  deps: FullHiExportDeps,
  ctx: ExportAuthContext,
  format: 'csv' | 'json',
): Promise<FullHiExportResult> {
  const providerId = ctx.providerId;

  // Audit: export requested
  await deps.auditLogger?.log({
    action: 'export.full_hi_requested',
    resourceType: 'export',
    resourceId: providerId,
    actorType: 'physician',
    metadata: { providerId, format },
  });

  // 1. Retrieve all HI
  const hi = await deps.exportRepo.getCompleteHealthInformation(providerId);

  // 2. Build entity counts for the manifest
  const entityCounts = buildEntityCounts(hi);

  // 3. Serialise each entity type
  const fileExtension = format === 'csv' ? 'csv' : 'json';

  const entityFiles: Array<{ name: string; content: string }> = [];

  // We use a helper to add only non-empty entities
  const addEntity = (name: string, rows: unknown[]) => {
    const content = serialiseEntity(rows, format);
    if (content && content !== '[]' && content !== '') {
      entityFiles.push({ name: `${name}.${fileExtension}`, content });
    }
  };

  addEntity('patients', hi.patients);
  addEntity('claims', hi.claims);
  addEntity('claim_audit_history', hi.claimAuditHistory);
  addEntity('shifts', hi.shifts);
  addEntity('claim_exports', hi.claimExports);
  addEntity('ahcip_claim_details', hi.ahcipClaimDetails);
  addEntity('ahcip_batches', hi.ahcipBatches);
  addEntity('wcb_claim_details', hi.wcbClaimDetails);
  addEntity('wcb_batches', hi.wcbBatches);
  addEntity('wcb_remittance_imports', hi.wcbRemittanceImports);
  if (hi.provider) {
    entityFiles.push({
      name: `provider.${fileExtension}`,
      content: serialiseEntity([hi.provider], format),
    });
  }
  addEntity('business_arrangements', hi.businessArrangements);
  addEntity('practice_locations', hi.practiceLocations);
  addEntity('wcb_configurations', hi.wcbConfigurations);
  addEntity('delegate_relationships', hi.delegateRelationships);
  addEntity('submission_preferences', hi.submissionPreferences);
  addEntity('hlink_configurations', hi.hlinkConfigurations);
  addEntity('pcpcm_enrolments', hi.pcpcmEnrolments);
  addEntity('pcpcm_payments', hi.pcpcmPayments);
  addEntity('pcpcm_panel_estimates', hi.pcpcmPanelEstimates);
  addEntity('analytics_cache', hi.analyticsCache);
  addEntity('generated_reports', hi.generatedReports);
  addEntity('report_subscriptions', hi.reportSubscriptions);
  addEntity('ai_provider_learning', hi.aiProviderLearning);
  addEntity('ai_suggestion_events', hi.aiSuggestionEvents);
  addEntity('ed_shifts', hi.edShifts);
  addEntity('favourite_codes', hi.favouriteCodes);
  if (hi.subscription) {
    entityFiles.push({
      name: `subscription.${fileExtension}`,
      content: serialiseEntity([hi.subscription], format),
    });
  }
  addEntity('ima_amendment_responses', hi.imaAmendmentResponses);
  addEntity('audit_log', hi.auditLog);

  // 4. Build manifest
  const manifest = {
    export_date: new Date().toISOString(),
    provider_id: providerId,
    format,
    entity_counts: entityCounts,
    schema_version: EXPORT_SCHEMA_VERSION,
  };

  // 5. Create ZIP archive
  const archive = archiver.create('zip', { zlib: { level: 9 } });
  const passThrough = new PassThrough();
  const chunks: Buffer[] = [];

  const bufferPromise = new Promise<Buffer>((resolve, reject) => {
    passThrough.on('data', (chunk: Buffer) => chunks.push(chunk));
    passThrough.on('end', () => resolve(Buffer.concat(chunks)));
    passThrough.on('error', reject);
    archive.on('error', reject);
  });

  archive.pipe(passThrough);

  // Add manifest
  archive.append(JSON.stringify(manifest, null, 2), { name: 'manifest.json' });

  // Add entity files
  for (const file of entityFiles) {
    archive.append(file.content, { name: file.name });
  }

  await archive.finalize();
  const zipBuffer = await bufferPromise;

  // 6. Upload to object storage
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const objectKey = `exports/${providerId}/${timestamp}.zip`;
  await deps.objectStorage.uploadBuffer(objectKey, zipBuffer, 'application/zip');

  // 7. Generate presigned URL
  const expiresInSeconds = FULL_EXPORT_URL_EXPIRY_HOURS * 60 * 60;
  const downloadUrl = await deps.objectStorage.getPresignedUrl(objectKey, expiresInSeconds);
  const expiresAt = new Date(Date.now() + expiresInSeconds * 1000);

  // 8. Create report record
  const report = await deps.reportRepo.createReport({
    providerId,
    reportType: 'FULL_DATA_PORTABILITY',
    format,
    filePath: objectKey,
    fileSizeBytes: zipBuffer.length,
    downloadLinkExpiresAt: expiresAt,
    status: 'ready',
  });

  // 9. Audit: export ready
  await deps.auditLogger?.log({
    action: 'export.full_hi_ready',
    resourceType: 'export',
    resourceId: report.reportId,
    actorType: 'physician',
    metadata: { providerId, format, fileSizeBytes: zipBuffer.length },
  });

  // 10. Emit notification
  deps.eventEmitter?.emit('FULL_HI_EXPORT_READY', {
    reportId: report.reportId,
    providerId,
    format,
    downloadUrl,
    expiresAt: expiresAt.toISOString(),
  });

  return {
    reportId: report.reportId,
    downloadUrl,
    expiresAt: expiresAt.toISOString(),
  };
}
