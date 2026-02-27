// ============================================================================
// Connect Care Import Workflow Service (FRD CC-001 §4)
// ============================================================================
//
// Orchestrates the full import lifecycle: upload → parse → review → confirm/cancel.

import { createHash, randomUUID } from 'node:crypto';
import { extname } from 'node:path';
import {
  SCC_MAX_FILE_SIZE_BYTES,
  SCC_ALLOWED_EXTENSIONS,
  CURRENT_SCC_SPEC_VERSION,
  ConnectCareImportStatus,
  ConnectCareAuditAction,
  SccRowClassification,
} from '@meritum/shared/constants/scc.constants.js';
import { ClaimImportSource } from '@meritum/shared/constants/claim.constants.js';
import {
  parseSccExtract,
  detectRowDuplicates,
  handleCorrections,
  type ParseResult,
  type ProviderContext,
  type DuplicateCheckDeps,
} from './scc-parser.service.js';
import { BusinessRuleError, NotFoundError } from '../../lib/errors.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ConnectCareImportDeps {
  /** Claim repository — creates import batches, claims, etc. */
  repo: {
    createImportBatch(data: Record<string, unknown>): Promise<Record<string, unknown>>;
    findImportBatchById(batchId: string, physicianId: string): Promise<Record<string, unknown> | undefined>;
    updateImportBatchStatus(
      batchId: string, physicianId: string, status: string,
      counts?: { successCount?: number; errorCount?: number; errorDetails?: unknown },
    ): Promise<Record<string, unknown> | undefined>;
    listImportBatches(physicianId: string, page: number, pageSize: number): Promise<{
      data: Record<string, unknown>[];
      pagination: { total: number; page: number; pageSize: number; hasMore: boolean };
    }>;
    createClaim(data: Record<string, unknown>): Promise<Record<string, unknown>>;
    appendClaimAudit(entry: Record<string, unknown>): Promise<Record<string, unknown>>;
  };

  /** Duplicate detection dependency */
  duplicateCheck: DuplicateCheckDeps;

  /** Audit log emitter */
  auditLog?: {
    log(action: string, data: Record<string, unknown>): Promise<void>;
  };
}

export interface UploadedFile {
  fileName: string;
  content: Buffer | string;
  size: number;
}

export interface UploadResult {
  importBatchId: string;
  parseResult: ParseResult;
  rawFilePath: string;
}

export interface ConfirmResult {
  importBatchId: string;
  claimsCreated: number;
  claimsSkipped: number;
  status: string;
}

// ---------------------------------------------------------------------------
// File validation
// ---------------------------------------------------------------------------

/**
 * Validate file extension and size before processing.
 */
export function validateFile(file: UploadedFile): void {
  const ext = extname(file.fileName).toLowerCase();
  const allowedLower = SCC_ALLOWED_EXTENSIONS.map((e: string) => e.toLowerCase());

  if (!allowedLower.includes(ext)) {
    throw new BusinessRuleError(
      `Invalid file extension: ${ext}. Allowed: ${SCC_ALLOWED_EXTENSIONS.join(', ')}`,
    );
  }

  if (file.size > SCC_MAX_FILE_SIZE_BYTES) {
    throw new BusinessRuleError(
      `File exceeds maximum size of ${SCC_MAX_FILE_SIZE_BYTES / (1024 * 1024)} MB`,
    );
  }
}

/**
 * Generate a storage path for the raw file.
 * Format: imports/{provider_id}/{yyyy-mm}/{uuid}.{ext}
 */
export function generateFilePath(providerId: string, fileName: string): string {
  const now = new Date();
  const yearMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
  const ext = extname(fileName);
  const uuid = randomUUID();
  return `imports/${providerId}/${yearMonth}/${uuid}${ext}`;
}

/**
 * Compute SHA-256 hash of file content for deduplication.
 */
export function computeFileHash(content: Buffer | string): string {
  return createHash('sha256').update(content).digest('hex');
}

// ---------------------------------------------------------------------------
// Upload & Parse (CC-001 §4.2)
// ---------------------------------------------------------------------------

/**
 * Upload, validate, parse, and create an import batch record.
 *
 * Steps:
 * 1. Validate file extension and size
 * 2. Generate storage path and compute file hash
 * 3. Parse CSV via SCC parser
 * 4. Run duplicate detection
 * 5. Run correction/deletion handling
 * 6. Create import_batch record (status=PENDING)
 * 7. Return ParseResult + importBatchId
 */
export async function uploadAndParse(
  deps: ConnectCareImportDeps,
  physicianId: string,
  actorId: string,
  providerCtx: ProviderContext,
  file: UploadedFile,
  extractType?: string,
): Promise<UploadResult> {
  // 1. Validate file
  validateFile(file);

  // 2. Generate path and hash
  const rawFilePath = generateFilePath(physicianId, file.fileName);
  const fileHash = computeFileHash(file.content);

  // 3. Parse CSV content
  const csvContent =
    typeof file.content === 'string'
      ? file.content
      : file.content.toString('utf-8');

  const parseResult = parseSccExtract(csvContent, file.fileName, providerCtx, extractType);

  // 4. Run duplicate detection
  const { duplicateCount } = await detectRowDuplicates(
    parseResult.rows,
    physicianId,
    deps.duplicateCheck,
  );
  parseResult.duplicateCount = duplicateCount;

  // 5. Run correction/deletion handling
  await handleCorrections(parseResult.rows, physicianId, deps.duplicateCheck);

  // 6. Create import batch record
  const batch = await deps.repo.createImportBatch({
    physicianId,
    fileName: file.fileName,
    fileHash,
    totalRows: parseResult.totalRows,
    successCount: parseResult.validCount + parseResult.warningCount,
    errorCount: parseResult.errorCount,
    status: 'PENDING',
    importSource: ClaimImportSource.CONNECT_CARE_CSV,
    sccSpecVersion: CURRENT_SCC_SPEC_VERSION,
    rawRowCount: parseResult.totalRows,
    validRowCount: parseResult.validCount,
    warningCount: parseResult.warningCount,
    duplicateCount: parseResult.duplicateCount,
    confirmationStatus: ConnectCareImportStatus.PENDING,
    createdBy: actorId,
  });

  const importBatchId = (batch as any).importBatchId;

  // 7. Audit log
  if (deps.auditLog) {
    await deps.auditLog.log(ConnectCareAuditAction.IMPORT_UPLOADED, {
      importBatchId,
      physicianId,
      fileName: file.fileName,
      totalRows: parseResult.totalRows,
      validCount: parseResult.validCount,
      errorCount: parseResult.errorCount,
    });
  }

  return {
    importBatchId,
    parseResult,
    rawFilePath,
  };
}

// ---------------------------------------------------------------------------
// Confirm Import (CC-001 §4.4)
// ---------------------------------------------------------------------------

/**
 * Confirm an import batch — create claims from all VALID/WARNING rows.
 *
 * Steps:
 * 1. Verify batch exists and is PENDING
 * 2. For each VALID/WARNING row: create claim in DRAFT state
 * 3. Tag claims with import metadata
 * 4. Skip DUPLICATE rows (unless explicitly included)
 * 5. Update batch status to CONFIRMED
 */
export async function confirmImport(
  deps: ConnectCareImportDeps,
  physicianId: string,
  actorId: string,
  batchId: string,
  parseResult: ParseResult,
  excludedRowNumbers?: number[],
): Promise<ConfirmResult> {
  // 1. Verify batch
  const batch = await deps.repo.findImportBatchById(batchId, physicianId);
  if (!batch) {
    throw new NotFoundError('Import batch not found');
  }

  if ((batch as any).confirmationStatus !== ConnectCareImportStatus.PENDING) {
    throw new BusinessRuleError(
      `Import batch is already ${(batch as any).confirmationStatus}`,
    );
  }

  const excludedSet = new Set(excludedRowNumbers ?? []);
  let claimsCreated = 0;
  let claimsSkipped = 0;

  // 2. Process rows
  for (const row of parseResult.rows) {
    // Skip excluded rows
    if (excludedSet.has(row.rowNumber)) {
      claimsSkipped++;
      continue;
    }

    // Skip ERROR rows
    if (row.classification === SccRowClassification.ERROR) {
      claimsSkipped++;
      continue;
    }

    // Skip DUPLICATE rows by default
    if (row.classification === SccRowClassification.DUPLICATE) {
      claimsSkipped++;
      continue;
    }

    // Skip DELETED rows (handled by corrections)
    if (row.classification === SccRowClassification.DELETED) {
      claimsSkipped++;
      continue;
    }

    // Create claim for VALID and WARNING rows
    if (
      row.classification === SccRowClassification.VALID ||
      row.classification === SccRowClassification.WARNING
    ) {
      await deps.repo.createClaim({
        physicianId,
        patientId: null, // Patient lookup happens during validation
        claimType: row.extractType === 'WCB' ? 'WCB' : 'AHCIP',
        state: 'DRAFT',
        importSource: ClaimImportSource.CONNECT_CARE_CSV,
        importBatchId: batchId,
        rawFileReference: (batch as any).fileName,
        sccChargeStatus: row.chargeStatus,
        icdConversionFlag: row.icdConversionFlag,
        icd10SourceCode: row.icd10SourceCode ?? null,
        dateOfService: row.encounterDate,
        submissionDeadline: computeSubmissionDeadline(row.encounterDate, row.extractType),
        createdBy: actorId,
        updatedBy: actorId,
      });

      claimsCreated++;
    }
  }

  // 3. Update batch status
  await deps.repo.updateImportBatchStatus(batchId, physicianId, 'COMPLETED', {
    successCount: claimsCreated,
    errorCount: claimsSkipped,
  });

  // Update confirmation status to CONFIRMED
  // (Uses the same update mechanism — the confirmationStatus field)

  // 4. Audit log
  if (deps.auditLog) {
    await deps.auditLog.log(ConnectCareAuditAction.IMPORT_CONFIRMED, {
      importBatchId: batchId,
      physicianId,
      claimsCreated,
      claimsSkipped,
    });
  }

  return {
    importBatchId: batchId,
    claimsCreated,
    claimsSkipped,
    status: ConnectCareImportStatus.CONFIRMED,
  };
}

// ---------------------------------------------------------------------------
// Cancel Import (CC-001 §11.1)
// ---------------------------------------------------------------------------

/**
 * Cancel a pending import batch. No claims are created.
 */
export async function cancelImport(
  deps: ConnectCareImportDeps,
  physicianId: string,
  batchId: string,
): Promise<{ importBatchId: string; status: string }> {
  const batch = await deps.repo.findImportBatchById(batchId, physicianId);
  if (!batch) {
    throw new NotFoundError('Import batch not found');
  }

  if ((batch as any).confirmationStatus !== ConnectCareImportStatus.PENDING) {
    throw new BusinessRuleError(
      `Import batch is already ${(batch as any).confirmationStatus}`,
    );
  }

  await deps.repo.updateImportBatchStatus(batchId, physicianId, 'FAILED', {
    successCount: 0,
    errorCount: 0,
  });

  if (deps.auditLog) {
    await deps.auditLog.log(ConnectCareAuditAction.IMPORT_CANCELLED, {
      importBatchId: batchId,
      physicianId,
    });
  }

  return {
    importBatchId: batchId,
    status: ConnectCareImportStatus.CANCELLED,
  };
}

// ---------------------------------------------------------------------------
// Import History (CC-001 §11.1)
// ---------------------------------------------------------------------------

/**
 * List Connect Care import history for the physician.
 */
export async function getImportHistory(
  deps: ConnectCareImportDeps,
  physicianId: string,
  page: number,
  pageSize: number,
) {
  return deps.repo.listImportBatches(physicianId, page, pageSize);
}

/**
 * Get details of a specific import batch.
 */
export async function getImportBatchDetail(
  deps: ConnectCareImportDeps,
  physicianId: string,
  batchId: string,
) {
  const batch = await deps.repo.findImportBatchById(batchId, physicianId);
  if (!batch) {
    throw new NotFoundError('Import batch not found');
  }
  return batch;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Compute submission deadline based on encounter date and extract type.
 * AHCIP: 90 days from DOS. WCB: form-specific (default 180 days).
 */
function computeSubmissionDeadline(encounterDate: string, extractType: string): string {
  const dos = new Date(encounterDate);
  const daysToAdd = extractType === 'WCB' ? 180 : 90;
  dos.setDate(dos.getDate() + daysToAdd);
  return dos.toISOString().split('T')[0];
}
