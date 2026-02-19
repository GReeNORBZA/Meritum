import { createHash } from 'node:crypto';
import type { PatientRepository, PaginatedResult } from './patient.repository.js';
import type { SelectPatient } from '@meritum/shared/schemas/db/patient.schema.js';
import {
  PatientAuditAction,
  PatientSearchMode,
  DEFAULT_PHN_PROVINCE,
  ImportStatus,
  CSV_COLUMN_MAPPINGS,
  CSV_GENDER_VALUE_MAPPINGS,
} from '@meritum/shared/constants/patient.constants.js';
import { validateAlbertaPhn, maskPhn } from '@meritum/shared/utils/phn.utils.js';
import { NotFoundError, ConflictError, ValidationError } from '../../lib/errors.js';

// ---------------------------------------------------------------------------
// Dependency interfaces (injected by handler / test)
// ---------------------------------------------------------------------------

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

export interface EventEmitter {
  emit(event: string, payload: Record<string, unknown>): void;
}

export interface PatientServiceDeps {
  repo: PatientRepository;
  auditRepo: AuditRepo;
  events: EventEmitter;
}

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

export interface CreatePatientInput {
  phn?: string | null;
  phnProvince?: string;
  firstName: string;
  middleName?: string;
  lastName: string;
  dateOfBirth: string;
  gender: string;
  phone?: string;
  email?: string;
  addressLine1?: string;
  addressLine2?: string;
  city?: string;
  province?: string;
  postalCode?: string;
  notes?: string;
}

export interface UpdatePatientInput {
  phn?: string | null;
  phnProvince?: string;
  firstName?: string;
  middleName?: string;
  lastName?: string;
  dateOfBirth?: string;
  gender?: string;
  phone?: string;
  email?: string;
  addressLine1?: string;
  addressLine2?: string;
  city?: string;
  province?: string;
  postalCode?: string;
  notes?: string;
}

export interface PatientSearchInput {
  phn?: string;
  name?: string;
  dob?: string;
  page: number;
  pageSize: number;
}

export interface PatientSearchResult {
  patients: SelectPatient[];
  total: number;
  page: number;
  page_size: number;
}

// ---------------------------------------------------------------------------
// Audit category constant
// ---------------------------------------------------------------------------

const AUDIT_CATEGORY = 'patient';

// ---------------------------------------------------------------------------
// PHN validation helper
// ---------------------------------------------------------------------------

/**
 * Validates PHN based on province rules:
 * - AB: 9-digit Luhn check
 * - Other provinces: 9–12 digit numeric (reciprocal billing, no Luhn)
 * - null/undefined: accepted (newborns, uninsured, WCB no-PHN)
 */
function validatePhn(
  phn: string | null | undefined,
  phnProvince: string | undefined,
): { valid: boolean; error?: string } {
  if (phn == null || phn === '') {
    return { valid: true };
  }

  const province = phnProvince ?? DEFAULT_PHN_PROVINCE;

  if (province === 'AB') {
    return validateAlbertaPhn(phn);
  }

  // Out-of-province reciprocal: accept 9–12 digit numeric
  if (!/^\d{9,12}$/.test(phn)) {
    return { valid: false, error: 'Out-of-province PHN must be 9-12 digits' };
  }

  return { valid: true };
}

// ---------------------------------------------------------------------------
// Service: createPatient
// ---------------------------------------------------------------------------

export async function createPatient(
  deps: PatientServiceDeps,
  physicianId: string,
  data: CreatePatientInput,
  actorId: string,
): Promise<SelectPatient> {
  // Validate PHN format
  const phnProvince = data.phnProvince ?? DEFAULT_PHN_PROVINCE;
  const phnValidation = validatePhn(data.phn, phnProvince);
  if (!phnValidation.valid) {
    throw new ValidationError(phnValidation.error!);
  }

  // Check PHN uniqueness within physician's active patients
  if (data.phn) {
    const existing = await deps.repo.findPatientByPhn(physicianId, data.phn);
    if (existing && existing.isActive) {
      throw new ConflictError('A patient with this PHN already exists');
    }
  }

  const patient = await deps.repo.createPatient({
    providerId: physicianId,
    phn: data.phn ?? null,
    phnProvince,
    firstName: data.firstName,
    middleName: data.middleName ?? null,
    lastName: data.lastName,
    dateOfBirth: data.dateOfBirth,
    gender: data.gender,
    phone: data.phone ?? null,
    email: data.email ?? null,
    addressLine1: data.addressLine1 ?? null,
    addressLine2: data.addressLine2 ?? null,
    city: data.city ?? null,
    province: data.province ?? null,
    postalCode: data.postalCode ?? null,
    notes: data.notes ?? null,
    createdBy: actorId,
  });

  // Audit log — PHN masked, notes excluded
  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: PatientAuditAction.CREATED,
    category: AUDIT_CATEGORY,
    resourceType: 'patient',
    resourceId: patient.patientId,
    detail: {
      phn: data.phn ? maskPhn(data.phn) : null,
      firstName: data.firstName,
      lastName: data.lastName,
      source: 'MANUAL',
    },
  });

  deps.events.emit(PatientAuditAction.CREATED, {
    patientId: patient.patientId,
    physicianId,
    actorId,
  });

  return patient;
}

// ---------------------------------------------------------------------------
// Service: getPatient
// ---------------------------------------------------------------------------

export async function getPatient(
  deps: PatientServiceDeps,
  patientId: string,
  physicianId: string,
): Promise<SelectPatient | null> {
  const patient = await deps.repo.findPatientById(patientId, physicianId);
  return patient ?? null;
}

// ---------------------------------------------------------------------------
// Service: updatePatient
// ---------------------------------------------------------------------------

export async function updatePatient(
  deps: PatientServiceDeps,
  patientId: string,
  physicianId: string,
  data: UpdatePatientInput,
  actorId: string,
): Promise<SelectPatient> {
  // Fetch existing patient to compute diff
  const existing = await deps.repo.findPatientById(patientId, physicianId);
  if (!existing) {
    throw new NotFoundError('Patient');
  }

  // If PHN is being changed, validate and check uniqueness
  const phnChanging =
    data.phn !== undefined && data.phn !== existing.phn;

  if (phnChanging && data.phn != null) {
    const phnProvince = data.phnProvince ?? existing.phnProvince ?? DEFAULT_PHN_PROVINCE;
    const phnValidation = validatePhn(data.phn, phnProvince);
    if (!phnValidation.valid) {
      throw new ValidationError(phnValidation.error!);
    }

    // Check uniqueness within physician's active patients (excluding self)
    const duplicate = await deps.repo.findPatientByPhn(physicianId, data.phn);
    if (duplicate && duplicate.patientId !== patientId && duplicate.isActive) {
      throw new ConflictError('A patient with this PHN already exists');
    }
  }

  // Build update payload and diff
  const diff: Record<string, { old: unknown; new: unknown }> = {};
  const updatePayload: Record<string, unknown> = {};

  const fieldMap: Record<string, string> = {
    phn: 'phn',
    phnProvince: 'phnProvince',
    firstName: 'firstName',
    middleName: 'middleName',
    lastName: 'lastName',
    dateOfBirth: 'dateOfBirth',
    gender: 'gender',
    phone: 'phone',
    email: 'email',
    addressLine1: 'addressLine1',
    addressLine2: 'addressLine2',
    city: 'city',
    province: 'province',
    postalCode: 'postalCode',
    notes: 'notes',
  };

  for (const [inputKey, dbKey] of Object.entries(fieldMap)) {
    const newValue = data[inputKey as keyof UpdatePatientInput];
    if (newValue !== undefined) {
      const oldValue = existing[dbKey as keyof SelectPatient];
      if (newValue !== oldValue) {
        // Never include notes in audit diff
        if (inputKey !== 'notes') {
          const oldForDiff = inputKey === 'phn' && oldValue ? maskPhn(oldValue as string) : oldValue;
          const newForDiff = inputKey === 'phn' && newValue ? maskPhn(newValue as string) : newValue;
          diff[dbKey] = { old: oldForDiff, new: newForDiff };
        }
        updatePayload[dbKey] = newValue;
      }
    }
  }

  // If nothing actually changed, return existing
  if (Object.keys(updatePayload).length === 0) {
    return existing;
  }

  const updated = await deps.repo.updatePatient(patientId, physicianId, updatePayload);
  if (!updated) {
    throw new NotFoundError('Patient');
  }

  // Audit log with field-level diff (PHNs masked, notes excluded)
  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: PatientAuditAction.UPDATED,
    category: AUDIT_CATEGORY,
    resourceType: 'patient',
    resourceId: patientId,
    detail: { changes: diff },
  });

  deps.events.emit(PatientAuditAction.UPDATED, {
    patientId,
    physicianId,
    actorId,
    changedFields: Object.keys(diff),
  });

  return updated;
}

// ---------------------------------------------------------------------------
// Service: deactivatePatient
// ---------------------------------------------------------------------------

export async function deactivatePatient(
  deps: PatientServiceDeps,
  patientId: string,
  physicianId: string,
  actorId: string,
): Promise<SelectPatient> {
  const patient = await deps.repo.findPatientById(patientId, physicianId);
  if (!patient) {
    throw new NotFoundError('Patient');
  }

  if (!patient.isActive) {
    throw new ValidationError('Patient is already deactivated');
  }

  const deactivated = await deps.repo.deactivatePatient(patientId, physicianId);
  if (!deactivated) {
    throw new NotFoundError('Patient');
  }

  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: PatientAuditAction.DEACTIVATED,
    category: AUDIT_CATEGORY,
    resourceType: 'patient',
    resourceId: patientId,
    detail: {
      phn: patient.phn ? maskPhn(patient.phn) : null,
      firstName: patient.firstName,
      lastName: patient.lastName,
    },
  });

  deps.events.emit(PatientAuditAction.DEACTIVATED, {
    patientId,
    physicianId,
    actorId,
  });

  return deactivated;
}

// ---------------------------------------------------------------------------
// Service: reactivatePatient
// ---------------------------------------------------------------------------

export async function reactivatePatient(
  deps: PatientServiceDeps,
  patientId: string,
  physicianId: string,
  actorId: string,
): Promise<SelectPatient> {
  const patient = await deps.repo.findPatientById(patientId, physicianId);
  if (!patient) {
    throw new NotFoundError('Patient');
  }

  if (patient.isActive) {
    throw new ValidationError('Patient is already active');
  }

  const reactivated = await deps.repo.reactivatePatient(patientId, physicianId);
  if (!reactivated) {
    throw new NotFoundError('Patient');
  }

  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: PatientAuditAction.REACTIVATED,
    category: AUDIT_CATEGORY,
    resourceType: 'patient',
    resourceId: patientId,
    detail: {
      phn: patient.phn ? maskPhn(patient.phn) : null,
      firstName: patient.firstName,
      lastName: patient.lastName,
    },
  });

  deps.events.emit(PatientAuditAction.REACTIVATED, {
    patientId,
    physicianId,
    actorId,
  });

  return reactivated;
}

// ---------------------------------------------------------------------------
// Service: searchPatients
// ---------------------------------------------------------------------------

/**
 * Determine search mode from the provided criteria:
 * - phn only → PHN_LOOKUP
 * - name only → NAME_SEARCH
 * - dob only → DOB_SEARCH
 * - multiple criteria → COMBINED
 */
function determineSearchMode(
  query: PatientSearchInput,
): PatientSearchMode {
  const hasPhn = !!query.phn;
  const hasName = !!query.name;
  const hasDob = !!query.dob;

  const criteriaCount = [hasPhn, hasName, hasDob].filter(Boolean).length;

  if (criteriaCount > 1) return PatientSearchMode.COMBINED;
  if (hasPhn) return PatientSearchMode.PHN_LOOKUP;
  if (hasName) return PatientSearchMode.NAME_SEARCH;
  if (hasDob) return PatientSearchMode.DOB_SEARCH;

  // No criteria — fall back to combined (empty result)
  return PatientSearchMode.COMBINED;
}

export async function searchPatients(
  deps: PatientServiceDeps,
  physicianId: string,
  query: PatientSearchInput,
  actorId: string,
): Promise<PatientSearchResult> {
  const mode = determineSearchMode(query);

  let patients: SelectPatient[] = [];
  let total: number = 0;

  switch (mode) {
    case PatientSearchMode.PHN_LOOKUP: {
      const result = await deps.repo.searchByPhn(physicianId, query.phn!);
      patients = result ? [result] : [];
      total = patients.length;
      break;
    }
    case PatientSearchMode.NAME_SEARCH: {
      const result = await deps.repo.searchByName(
        physicianId,
        query.name!,
        query.page,
        query.pageSize,
      );
      patients = result.data;
      total = result.pagination.total;
      break;
    }
    case PatientSearchMode.DOB_SEARCH: {
      const result = await deps.repo.searchByDob(
        physicianId,
        new Date(query.dob!),
        query.page,
        query.pageSize,
      );
      patients = result.data;
      total = result.pagination.total;
      break;
    }
    case PatientSearchMode.COMBINED: {
      const filters: { phn?: string; name?: string; dob?: Date } = {};
      if (query.phn) filters.phn = query.phn;
      if (query.name) filters.name = query.name;
      if (query.dob) filters.dob = new Date(query.dob);

      const result = await deps.repo.searchCombined(
        physicianId,
        filters,
        query.page,
        query.pageSize,
      );
      patients = result.data;
      total = result.pagination.total;
      break;
    }
  }

  // Audit log — log search parameters only, never results
  const auditDetail: Record<string, unknown> = { mode };
  if (query.phn) auditDetail.phn = maskPhn(query.phn);
  if (query.name) auditDetail.name = query.name;
  if (query.dob) auditDetail.dob = query.dob;
  auditDetail.resultCount = total;

  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: PatientAuditAction.SEARCHED,
    category: AUDIT_CATEGORY,
    resourceType: 'patient',
    resourceId: null,
    detail: auditDetail,
  });

  return {
    patients,
    total,
    page: query.page,
    page_size: query.pageSize,
  };
}

// ---------------------------------------------------------------------------
// Service: getRecentPatients
// ---------------------------------------------------------------------------

export async function getRecentPatients(
  deps: PatientServiceDeps,
  physicianId: string,
  limit: number,
): Promise<SelectPatient[]> {
  return deps.repo.getRecentPatients(physicianId, limit);
}

// ===========================================================================
// CSV Bulk Import Workflow
// ===========================================================================

// ---------------------------------------------------------------------------
// Import types
// ---------------------------------------------------------------------------

export interface ImportPreviewRow {
  rowIndex: number;
  mapped: Record<string, string | null>;
  warnings: string[];
}

export interface ImportPreview {
  importId: string;
  delimiter: string;
  headers: string[];
  mapping: Record<string, string | null>;
  previewRows: ImportPreviewRow[];
  totalRows: number;
}

export interface ImportResult {
  importId: string;
  status: string;
  totalRows: number;
  created: number;
  updated: number;
  skipped: number;
  errors: number;
  errorDetails: Array<{ row: number; field?: string; message: string }>;
}

// ---------------------------------------------------------------------------
// In-memory parsed row storage (per import batch)
// ---------------------------------------------------------------------------

const parsedRowsCache = new Map<
  string,
  {
    rows: string[][];
    headers: string[];
    delimiter: string;
    mapping: Record<string, string | null>;
  }
>();

// ---------------------------------------------------------------------------
// CSV parsing helpers
// ---------------------------------------------------------------------------

/**
 * Auto-detect CSV delimiter from first line. Tries comma, tab, pipe.
 */
function detectDelimiter(firstLine: string): string {
  const candidates: Array<{ delim: string; count: number }> = [
    { delim: ',', count: firstLine.split(',').length },
    { delim: '\t', count: firstLine.split('\t').length },
    { delim: '|', count: firstLine.split('|').length },
  ];

  // Pick delimiter that produces most columns (at least 2)
  candidates.sort((a, b) => b.count - a.count);
  return candidates[0].count >= 2 ? candidates[0].delim : ',';
}

/**
 * Detect if the first row looks like a header (contains common column names).
 */
function detectHasHeaders(firstRow: string[]): boolean {
  const allAliases = new Set<string>();
  for (const aliases of Object.values(CSV_COLUMN_MAPPINGS)) {
    for (const alias of aliases) {
      allAliases.add(alias.toLowerCase());
    }
  }

  // If any cell in the first row matches a known column alias, treat as header
  return firstRow.some((cell) => allAliases.has(cell.trim().toLowerCase()));
}

/**
 * Parse CSV content into rows of cells, handling quoted fields.
 */
function parseCsvContent(content: string, delimiter: string): string[][] {
  const rows: string[][] = [];
  const lines = content.split(/\r?\n/);

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === '') continue;

    const cells: string[] = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < trimmed.length; i++) {
      const char = trimmed[i];

      if (inQuotes) {
        if (char === '"') {
          if (i + 1 < trimmed.length && trimmed[i + 1] === '"') {
            current += '"';
            i++; // Skip escaped quote
          } else {
            inQuotes = false;
          }
        } else {
          current += char;
        }
      } else if (char === '"') {
        inQuotes = true;
      } else if (char === delimiter) {
        cells.push(current.trim());
        current = '';
      } else {
        current += char;
      }
    }
    cells.push(current.trim());
    rows.push(cells);
  }

  return rows;
}

/**
 * Auto-map detected CSV headers to Meritum patient fields.
 * Returns a mapping: { meritumField: csvColumnIndex | null }
 */
function autoMapColumns(
  headers: string[],
): Record<string, string | null> {
  const mapping: Record<string, string | null> = {};

  for (const [field, aliases] of Object.entries(CSV_COLUMN_MAPPINGS)) {
    const lowerAliases = aliases.map((a: string) => a.toLowerCase());
    const matchIndex = headers.findIndex((h) =>
      lowerAliases.includes(h.trim().toLowerCase()),
    );

    mapping[field] = matchIndex >= 0 ? headers[matchIndex] : null;
  }

  return mapping;
}

/**
 * Map a raw CSV row to patient fields using the column mapping.
 * Returns mapped values and validation warnings.
 */
function mapRow(
  row: string[],
  headers: string[],
  mapping: Record<string, string | null>,
): { mapped: Record<string, string | null>; warnings: string[] } {
  const mapped: Record<string, string | null> = {};
  const warnings: string[] = [];

  for (const [field, headerName] of Object.entries(mapping)) {
    if (headerName == null) {
      mapped[field] = null;
      continue;
    }

    const colIndex = headers.indexOf(headerName);
    if (colIndex < 0 || colIndex >= row.length) {
      mapped[field] = null;
      continue;
    }

    const rawValue = row[colIndex]?.trim() ?? '';
    if (rawValue === '') {
      mapped[field] = null;
      continue;
    }

    // Gender normalization
    if (field === 'gender') {
      const normalized =
        CSV_GENDER_VALUE_MAPPINGS[rawValue] ?? CSV_GENDER_VALUE_MAPPINGS[rawValue.charAt(0).toUpperCase() + rawValue.slice(1).toLowerCase()];
      if (normalized) {
        mapped[field] = normalized;
      } else {
        mapped[field] = rawValue;
        warnings.push(`Unknown gender value: "${rawValue}"`);
      }
      continue;
    }

    mapped[field] = rawValue;
  }

  // Validate required fields in preview
  const requiredFields = ['first_name', 'last_name', 'date_of_birth', 'gender'];
  for (const req of requiredFields) {
    if (!mapped[req]) {
      warnings.push(`Missing required field: ${req}`);
    }
  }

  // Validate PHN if present
  if (mapped.phn) {
    const phnResult = validateAlbertaPhn(mapped.phn);
    if (!phnResult.valid) {
      warnings.push(`Invalid PHN: ${phnResult.error}`);
    }
  }

  return { mapped, warnings };
}

// ---------------------------------------------------------------------------
// Service: initiateImport
// ---------------------------------------------------------------------------

export async function initiateImport(
  deps: PatientServiceDeps,
  physicianId: string,
  file: Buffer,
  fileName: string,
  actorId: string,
): Promise<{ importId: string }> {
  // Compute SHA-256 hash
  const fileHash = createHash('sha256').update(file).digest('hex');

  // Check for duplicate upload
  const existing = await deps.repo.findImportByFileHash(physicianId, fileHash);
  if (existing) {
    throw new ConflictError('This file has already been imported');
  }

  // Parse CSV
  const content = file.toString('utf-8');
  const lines = content.split(/\r?\n/).filter((l) => l.trim() !== '');
  if (lines.length === 0) {
    throw new ValidationError('CSV file is empty');
  }

  const delimiter = detectDelimiter(lines[0]);
  const allRows = parseCsvContent(content, delimiter);

  if (allRows.length === 0) {
    throw new ValidationError('CSV file contains no data');
  }

  const hasHeaders = detectHasHeaders(allRows[0]);
  const headers = hasHeaders ? allRows[0] : allRows[0].map((_, i) => `column_${i + 1}`);
  const dataRows = hasHeaders ? allRows.slice(1) : allRows;

  // Auto-map columns
  const mapping = autoMapColumns(headers);

  // Create import batch record
  const batch = await deps.repo.createImportBatch({
    physicianId,
    fileName,
    fileHash,
    totalRows: dataRows.length,
    status: ImportStatus.PENDING,
    createdBy: actorId,
  });

  // Store parsed rows in memory cache
  parsedRowsCache.set(batch.importId, {
    rows: dataRows,
    headers,
    delimiter,
    mapping,
  });

  return { importId: batch.importId };
}

// ---------------------------------------------------------------------------
// Service: getImportPreview
// ---------------------------------------------------------------------------

export async function getImportPreview(
  deps: PatientServiceDeps,
  importId: string,
  physicianId: string,
): Promise<ImportPreview> {
  const batch = await deps.repo.findImportBatchById(importId, physicianId);
  if (!batch) {
    throw new NotFoundError('Import batch');
  }

  const cached = parsedRowsCache.get(importId);
  if (!cached) {
    throw new ValidationError('Import data has expired. Please re-upload the file.');
  }

  // Generate preview for first 10 rows
  const previewCount = Math.min(10, cached.rows.length);
  const previewRows: ImportPreviewRow[] = [];

  for (let i = 0; i < previewCount; i++) {
    const { mapped, warnings } = mapRow(cached.rows[i], cached.headers, cached.mapping);
    previewRows.push({
      rowIndex: i,
      mapped,
      warnings,
    });
  }

  return {
    importId,
    delimiter: cached.delimiter,
    headers: cached.headers,
    mapping: cached.mapping,
    previewRows,
    totalRows: cached.rows.length,
  };
}

// ---------------------------------------------------------------------------
// Service: updateImportMapping
// ---------------------------------------------------------------------------

export async function updateImportMapping(
  deps: PatientServiceDeps,
  importId: string,
  physicianId: string,
  mapping: Record<string, string | null>,
): Promise<void> {
  const batch = await deps.repo.findImportBatchById(importId, physicianId);
  if (!batch) {
    throw new NotFoundError('Import batch');
  }

  if (batch.status !== ImportStatus.PENDING) {
    throw new ValidationError('Import has already been processed');
  }

  const cached = parsedRowsCache.get(importId);
  if (!cached) {
    throw new ValidationError('Import data has expired. Please re-upload the file.');
  }

  cached.mapping = mapping;
}

// ---------------------------------------------------------------------------
// Service: commitImport
// ---------------------------------------------------------------------------

export async function commitImport(
  deps: PatientServiceDeps,
  importId: string,
  physicianId: string,
  actorId: string,
): Promise<ImportResult> {
  const batch = await deps.repo.findImportBatchById(importId, physicianId);
  if (!batch) {
    throw new NotFoundError('Import batch');
  }

  if (batch.status !== ImportStatus.PENDING) {
    throw new ValidationError('Import has already been processed');
  }

  const cached = parsedRowsCache.get(importId);
  if (!cached) {
    throw new ValidationError('Import data has expired. Please re-upload the file.');
  }

  // Set status to PROCESSING
  await deps.repo.updateImportStatus(importId, ImportStatus.PROCESSING);

  let created = 0;
  let updated = 0;
  let skipped = 0;
  let errors = 0;
  const errorDetails: Array<{ row: number; field?: string; message: string }> = [];
  const seenPhns = new Set<string>();

  try {
    for (let i = 0; i < cached.rows.length; i++) {
      const { mapped, warnings } = mapRow(cached.rows[i], cached.headers, cached.mapping);
      const rowNum = i + 1;

      // Check required fields
      const firstName = mapped.first_name;
      const lastName = mapped.last_name;
      const dob = mapped.date_of_birth;
      const gender = mapped.gender;

      if (!firstName || !lastName || !dob || !gender) {
        const missingFields = [];
        if (!firstName) missingFields.push('first_name');
        if (!lastName) missingFields.push('last_name');
        if (!dob) missingFields.push('date_of_birth');
        if (!gender) missingFields.push('gender');
        errorDetails.push({
          row: rowNum,
          message: `Missing required fields: ${missingFields.join(', ')}`,
        });
        errors++;
        continue;
      }

      // Validate PHN if present
      const phn = mapped.phn ?? null;
      if (phn) {
        const phnResult = validateAlbertaPhn(phn);
        if (!phnResult.valid) {
          errorDetails.push({
            row: rowNum,
            field: 'phn',
            message: phnResult.error!,
          });
          errors++;
          continue;
        }

        // Check for duplicate PHN within this file
        if (seenPhns.has(phn)) {
          skipped++;
          continue;
        }
        seenPhns.add(phn);

        // Check for existing patient with this PHN
        const existingPatient = await deps.repo.findPatientByPhn(physicianId, phn);
        if (existingPatient) {
          // Update existing patient — non-null import values overwrite
          const updateData: Record<string, unknown> = {};
          if (firstName) updateData.firstName = firstName;
          if (lastName) updateData.lastName = lastName;
          if (dob) updateData.dateOfBirth = dob;
          if (gender) updateData.gender = gender;
          if (mapped.phone) updateData.phone = mapped.phone;
          if (mapped.address_line_1) updateData.addressLine1 = mapped.address_line_1;
          if (mapped.city) updateData.city = mapped.city;
          if (mapped.postal_code) updateData.postalCode = mapped.postal_code;

          await deps.repo.updatePatient(
            existingPatient.patientId,
            physicianId,
            updateData,
          );
          updated++;
          continue;
        }
      }

      // Create new patient
      await deps.repo.createPatient({
        providerId: physicianId,
        phn,
        phnProvince: DEFAULT_PHN_PROVINCE,
        firstName,
        middleName: null,
        lastName,
        dateOfBirth: dob,
        gender,
        phone: mapped.phone ?? null,
        email: null,
        addressLine1: mapped.address_line_1 ?? null,
        addressLine2: null,
        city: mapped.city ?? null,
        province: null,
        postalCode: mapped.postal_code ?? null,
        notes: null,
        createdBy: actorId,
      });
      created++;
    }

    // Set status to COMPLETED
    const counts = { created, updated, skipped, error: errors };
    await deps.repo.updateImportStatus(
      importId,
      ImportStatus.COMPLETED,
      counts,
      errorDetails.length > 0 ? errorDetails : undefined,
    );

    // Emit audit event
    await deps.auditRepo.appendAuditLog({
      userId: actorId,
      action: PatientAuditAction.IMPORT_COMPLETED,
      category: AUDIT_CATEGORY,
      resourceType: 'import_batch',
      resourceId: importId,
      detail: {
        fileName: batch.fileName,
        totalRows: cached.rows.length,
        created,
        updated,
        skipped,
        errors,
      },
    });

    deps.events.emit(PatientAuditAction.IMPORT_COMPLETED, {
      importId,
      physicianId,
      actorId,
      created,
      updated,
      skipped,
      errors,
    });

    // Clean up parsed rows cache
    parsedRowsCache.delete(importId);

    return {
      importId,
      status: ImportStatus.COMPLETED,
      totalRows: cached.rows.length,
      created,
      updated,
      skipped,
      errors,
      errorDetails,
    };
  } catch (err) {
    // If entire batch fails, mark as FAILED
    await deps.repo.updateImportStatus(
      importId,
      ImportStatus.FAILED,
      { created: 0, updated: 0, skipped: 0, error: cached.rows.length },
      [{ row: 0, message: 'Batch processing failed' }],
    );

    parsedRowsCache.delete(importId);

    throw err;
  }
}

// ---------------------------------------------------------------------------
// Service: getImportStatus
// ---------------------------------------------------------------------------

export async function getImportStatus(
  deps: PatientServiceDeps,
  importId: string,
  physicianId: string,
): Promise<ImportResult> {
  const batch = await deps.repo.findImportBatchById(importId, physicianId);
  if (!batch) {
    throw new NotFoundError('Import batch');
  }

  return {
    importId: batch.importId,
    status: batch.status,
    totalRows: batch.totalRows,
    created: batch.createdCount,
    updated: batch.updatedCount,
    skipped: batch.skippedCount,
    errors: batch.errorCount,
    errorDetails: (batch.errorDetails as Array<{ row: number; field?: string; message: string }>) ?? [],
  };
}

// ===========================================================================
// Patient Merge Workflow
// ===========================================================================

// ---------------------------------------------------------------------------
// Merge types
// ---------------------------------------------------------------------------

export interface MergePreview {
  surviving: SelectPatient;
  merged: SelectPatient;
  claimsToTransfer: number;
  fieldConflicts: Record<string, { surviving: unknown; merged: unknown }>;
}

export interface MergeResult {
  mergeId: string;
  claimsTransferred: number;
  fieldConflicts: Record<string, { surviving: unknown; merged: unknown }>;
}

// ---------------------------------------------------------------------------
// Service: getMergePreview
// ---------------------------------------------------------------------------

/**
 * Verify both patients belong to physician and are active. Return side-by-side
 * comparison highlighting field differences and claim transfer count
 * (draft/validated claims only).
 */
export async function getMergePreview(
  deps: PatientServiceDeps,
  physicianId: string,
  survivingId: string,
  mergedId: string,
): Promise<MergePreview> {
  const preview = await deps.repo.getMergePreview(physicianId, survivingId, mergedId);
  if (!preview) {
    throw new NotFoundError('Patient');
  }

  return {
    surviving: preview.surviving,
    merged: preview.merged,
    claimsToTransfer: preview.claimsToTransfer,
    fieldConflicts: preview.fieldConflicts,
  };
}

// ---------------------------------------------------------------------------
// Service: executeMerge
// ---------------------------------------------------------------------------

/**
 * Execute patient merge: delegate to repository (transactional), emit
 * patient.merged audit event with merge details, return merge_id.
 *
 * Merge rules enforced:
 * - Both patients must belong to the same physician
 * - Both patients must be active
 * - Surviving record's field values are kept for all conflicts
 * - Only draft/validated claims transferred; submitted claims retain original patient_id
 */
export async function executeMerge(
  deps: PatientServiceDeps,
  physicianId: string,
  survivingId: string,
  mergedId: string,
  actorId: string,
): Promise<MergeResult> {
  const result = await deps.repo.executeMerge(physicianId, survivingId, mergedId, actorId);
  if (!result) {
    throw new NotFoundError('Patient');
  }

  // Audit log — PHN values are already in fieldConflicts but we mask them
  const maskedConflicts: Record<string, { surviving: unknown; merged: unknown }> = {};
  for (const [field, values] of Object.entries(result.fieldConflicts)) {
    if (field === 'phn') {
      maskedConflicts[field] = {
        surviving: values.surviving ? maskPhn(values.surviving as string) : null,
        merged: values.merged ? maskPhn(values.merged as string) : null,
      };
    } else {
      maskedConflicts[field] = values;
    }
  }

  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: PatientAuditAction.MERGED,
    category: AUDIT_CATEGORY,
    resourceType: 'patient',
    resourceId: survivingId,
    detail: {
      surviving_patient_id: survivingId,
      merged_patient_id: mergedId,
      claims_transferred: result.claimsTransferred,
      field_conflicts: maskedConflicts,
    },
  });

  deps.events.emit(PatientAuditAction.MERGED, {
    mergeId: result.mergeId,
    physicianId,
    actorId,
    survivingPatientId: survivingId,
    mergedPatientId: mergedId,
    claimsTransferred: result.claimsTransferred,
  });

  return result;
}

// ---------------------------------------------------------------------------
// Service: getMergeHistory
// ---------------------------------------------------------------------------

/**
 * Return paginated merge history for the physician.
 */
export async function getMergeHistory(
  deps: PatientServiceDeps,
  physicianId: string,
  page: number,
  pageSize: number,
): Promise<PaginatedResult<any>> {
  return deps.repo.listMergeHistory(physicianId, page, pageSize);
}

// ===========================================================================
// Patient Export
// ===========================================================================

// ---------------------------------------------------------------------------
// Export types
// ---------------------------------------------------------------------------

export interface ExportRequest {
  exportId: string;
  rowCount: number;
  status: 'PROCESSING' | 'READY' | 'FAILED';
}

export interface ExportStatus {
  exportId: string;
  status: 'PROCESSING' | 'READY' | 'FAILED';
  rowCount: number;
  downloadUrl?: string;
}

// ---------------------------------------------------------------------------
// In-memory export storage (temporary — production uses DO Spaces)
// ---------------------------------------------------------------------------

const exportStore = new Map<
  string,
  {
    physicianId: string;
    csvContent: string;
    rowCount: number;
    status: 'PROCESSING' | 'READY' | 'FAILED';
    downloadUrl: string;
    createdAt: Date;
    expiresAt: Date;
    downloaded: boolean;
  }
>();

// ---------------------------------------------------------------------------
// Service: requestExport
// ---------------------------------------------------------------------------

/**
 * Generate CSV of all active patients (phn, first_name, last_name,
 * date_of_birth, gender, phone, address fields — NO notes).
 * Store as temporary file with time-limited (1 hour) authenticated download URL.
 * Emit patient.export_requested audit event with row count.
 */
export async function requestExport(
  deps: PatientServiceDeps,
  physicianId: string,
  actorId: string,
): Promise<ExportRequest> {
  const exportId = crypto.randomUUID();

  // Get all active patients (no notes)
  const rows = await deps.repo.exportActivePatients(physicianId);
  const rowCount = rows.length;

  // Build CSV content
  const csvHeaders = [
    'phn',
    'first_name',
    'last_name',
    'date_of_birth',
    'gender',
    'phone',
    'address_line_1',
    'address_line_2',
    'city',
    'province',
    'postal_code',
  ];
  const csvLines = [csvHeaders.join(',')];
  for (const row of rows) {
    const values = [
      escapeCsvValue(row.phn ?? ''),
      escapeCsvValue(row.firstName),
      escapeCsvValue(row.lastName),
      escapeCsvValue(row.dateOfBirth),
      escapeCsvValue(row.gender),
      escapeCsvValue(row.phone ?? ''),
      escapeCsvValue(row.addressLine1 ?? ''),
      escapeCsvValue(row.addressLine2 ?? ''),
      escapeCsvValue(row.city ?? ''),
      escapeCsvValue(row.province ?? ''),
      escapeCsvValue(row.postalCode ?? ''),
    ];
    csvLines.push(values.join(','));
  }
  const csvContent = csvLines.join('\n');

  // Store export with time-limited URL (1 hour expiry)
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 60 * 60 * 1000); // 1 hour
  const downloadUrl = `/api/v1/patients/exports/${exportId}/download`;

  exportStore.set(exportId, {
    physicianId,
    csvContent,
    rowCount,
    status: 'READY',
    downloadUrl,
    createdAt: now,
    expiresAt,
    downloaded: false,
  });

  // Audit log — never include PHI, only row count
  await deps.auditRepo.appendAuditLog({
    userId: actorId,
    action: PatientAuditAction.EXPORT_REQUESTED,
    category: AUDIT_CATEGORY,
    resourceType: 'patient_export',
    resourceId: exportId,
    detail: { rowCount },
  });

  deps.events.emit(PatientAuditAction.EXPORT_REQUESTED, {
    exportId,
    physicianId,
    actorId,
    rowCount,
  });

  return {
    exportId,
    rowCount,
    status: 'PROCESSING',
  };
}

/**
 * Escape a value for CSV output. Wraps in quotes if it contains commas,
 * quotes, or newlines. Doubles internal quotes.
 */
function escapeCsvValue(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

// ---------------------------------------------------------------------------
// Service: getExportStatus
// ---------------------------------------------------------------------------

/**
 * Return export status and download URL (if ready).
 * Emit patient.export_downloaded when URL is first accessed.
 */
export async function getExportStatus(
  deps: PatientServiceDeps,
  exportId: string,
  physicianId: string,
  actorId?: string,
): Promise<ExportStatus> {
  const entry = exportStore.get(exportId);
  if (!entry || entry.physicianId !== physicianId) {
    throw new NotFoundError('Export');
  }

  // Check expiry
  if (new Date() > entry.expiresAt) {
    exportStore.delete(exportId);
    throw new NotFoundError('Export');
  }

  // Emit download audit on first access
  if (entry.status === 'READY' && !entry.downloaded) {
    entry.downloaded = true;

    await deps.auditRepo.appendAuditLog({
      userId: actorId ?? null,
      action: PatientAuditAction.EXPORT_DOWNLOADED,
      category: AUDIT_CATEGORY,
      resourceType: 'patient_export',
      resourceId: exportId,
      detail: { rowCount: entry.rowCount },
    });

    deps.events.emit(PatientAuditAction.EXPORT_DOWNLOADED, {
      exportId,
      physicianId,
      rowCount: entry.rowCount,
    });
  }

  return {
    exportId,
    status: entry.status,
    rowCount: entry.rowCount,
    downloadUrl: entry.status === 'READY' ? entry.downloadUrl : undefined,
  };
}

// ===========================================================================
// Internal API (consumed by Domain 4)
// ===========================================================================

// ---------------------------------------------------------------------------
// Internal API types
// ---------------------------------------------------------------------------

export interface PatientClaimContextResult {
  patientId: string;
  phn: string | null;
  phnProvince: string | null;
  firstName: string;
  lastName: string;
  dateOfBirth: string;
  gender: string;
}

export interface ValidatePhnResult {
  valid: boolean;
  formatOk: boolean;
  exists: boolean;
  patientId?: string;
}

// ---------------------------------------------------------------------------
// Service: getPatientClaimContext
// ---------------------------------------------------------------------------

/**
 * Return minimal claim context: patient_id, phn, phn_province,
 * first_name, last_name, date_of_birth, gender.
 * Returns null if patient not found or not owned by physician.
 */
export async function getPatientClaimContext(
  deps: PatientServiceDeps,
  patientId: string,
  physicianId: string,
): Promise<PatientClaimContextResult | null> {
  return deps.repo.getPatientClaimContext(patientId, physicianId);
}

// ---------------------------------------------------------------------------
// Service: validatePhnService
// ---------------------------------------------------------------------------

/**
 * Validate PHN format (Luhn if AB) and check existence in physician's
 * registry. Return { valid, format_ok, exists, patient_id? }.
 */
export async function validatePhnService(
  deps: PatientServiceDeps,
  physicianId: string,
  phn: string,
): Promise<ValidatePhnResult> {
  // Check format first
  const formatCheck = validateAlbertaPhn(phn);
  if (!formatCheck.valid) {
    return { valid: false, formatOk: false, exists: false };
  }

  // Check existence in physician's registry
  const existsResult = await deps.repo.validatePhnExists(physicianId, phn);

  return {
    valid: true,
    formatOk: true,
    exists: existsResult.exists,
    patientId: existsResult.patientId,
  };
}

// ---------------------------------------------------------------------------
// Export internal stores and caches for testing
// ---------------------------------------------------------------------------

export { parsedRowsCache as _parsedRowsCache, exportStore as _exportStore };
