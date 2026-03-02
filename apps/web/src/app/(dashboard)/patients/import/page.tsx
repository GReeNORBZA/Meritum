'use client';

import * as React from 'react';
import { useState, useCallback } from 'react';
import Link from 'next/link';
import { ROUTES } from '@/config/routes';
import { api } from '@/lib/api/client';
import { FileUpload } from '@/components/forms/file-upload';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { ArrowLeft, ArrowRight, CheckCircle2, Loader2, Upload, AlertTriangle } from 'lucide-react';
import { toast } from 'sonner';

// ---------- Types ----------

interface CsvRow {
  [key: string]: string;
}

interface ColumnMapping {
  [csvColumn: string]: string | null;
}

interface ValidationResult {
  valid: CsvRow[];
  invalid: Array<{ row: number; errors: string[] }>;
  total: number;
}

// ---------- Constants ----------

const PATIENT_FIELDS = [
  { value: 'phn', label: 'PHN' },
  { value: 'first_name', label: 'First Name' },
  { value: 'last_name', label: 'Last Name' },
  { value: 'date_of_birth', label: 'Date of Birth' },
  { value: 'gender', label: 'Gender' },
  { value: 'phone', label: 'Phone' },
  { value: 'email', label: 'Email' },
  { value: 'address_line_1', label: 'Address Line 1' },
  { value: 'address_line_2', label: 'Address Line 2' },
  { value: 'city', label: 'City' },
  { value: 'province', label: 'Province' },
  { value: 'postal_code', label: 'Postal Code' },
] as const;

const AUTO_MAPPING: Record<string, string[]> = {
  phn: ['phn', 'healthnumber', 'ab_phn', 'health_number'],
  first_name: ['firstname', 'first', 'givenname', 'first_name', 'given_name'],
  last_name: ['lastname', 'last', 'surname', 'last_name', 'family_name'],
  date_of_birth: ['dob', 'dateofbirth', 'birthdate', 'date_of_birth', 'birth_date'],
  gender: ['gender', 'sex'],
  phone: ['phone', 'phonenumber', 'tel', 'phone_number'],
  email: ['email', 'emailaddress', 'email_address'],
  address_line_1: ['address', 'address1', 'street', 'address_line_1'],
  address_line_2: ['address2', 'apt', 'suite', 'address_line_2'],
  city: ['city', 'town'],
  province: ['province', 'prov', 'state'],
  postal_code: ['postalcode', 'postal', 'zip', 'postal_code'],
};

// ---------- CSV Parsing ----------

function parseCsv(text: string): { headers: string[]; rows: CsvRow[] } {
  const lines = text.split(/\r?\n/).filter((line) => line.trim().length > 0);
  if (lines.length === 0) return { headers: [], rows: [] };

  const headers = lines[0].split(',').map((h) => h.trim().replace(/^"|"$/g, ''));
  const rows: CsvRow[] = [];

  for (let i = 1; i < lines.length; i++) {
    const values = lines[i].split(',').map((v) => v.trim().replace(/^"|"$/g, ''));
    const row: CsvRow = {};
    headers.forEach((header, index) => {
      row[header] = values[index] ?? '';
    });
    rows.push(row);
  }

  return { headers, rows };
}

function autoDetectMapping(headers: string[]): ColumnMapping {
  const mapping: ColumnMapping = {};
  headers.forEach((header) => {
    const normalized = header.toLowerCase().replace(/[\s_-]/g, '');
    let matched = false;
    for (const [field, aliases] of Object.entries(AUTO_MAPPING)) {
      if (aliases.some((alias) => normalized === alias.replace(/[\s_-]/g, ''))) {
        mapping[header] = field;
        matched = true;
        break;
      }
    }
    if (!matched) {
      mapping[header] = null;
    }
  });
  return mapping;
}

// ---------- Step Components ----------

function StepUpload({
  onFilesParsed,
}: {
  onFilesParsed: (headers: string[], rows: CsvRow[]) => void;
}) {
  const [error, setError] = useState<string | null>(null);

  const handleUpload = useCallback(
    (files: File[]) => {
      if (files.length === 0) return;
      setError(null);

      const file = files[0];
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const text = e.target?.result as string;
          const { headers, rows } = parseCsv(text);
          if (headers.length === 0) {
            setError('The CSV file appears to be empty or incorrectly formatted.');
            return;
          }
          if (rows.length === 0) {
            setError('The CSV file contains headers but no data rows.');
            return;
          }
          onFilesParsed(headers, rows);
        } catch {
          setError('Failed to parse the CSV file. Please check the format.');
        }
      };
      reader.onerror = () => {
        setError('Failed to read the file. Please try again.');
      };
      reader.readAsText(file);
    },
    [onFilesParsed]
  );

  return (
    <div className="space-y-4">
      <FileUpload
        accept=".csv,text/csv"
        maxSize={5 * 1024 * 1024}
        maxFiles={1}
        onUpload={handleUpload}
      />
      {error && (
        <div className="flex items-center gap-2 rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}
      <div className="text-sm text-muted-foreground">
        <p className="font-medium">Expected CSV format:</p>
        <ul className="mt-1 list-inside list-disc space-y-1">
          <li>UTF-8 encoded CSV file</li>
          <li>First row must be column headers</li>
          <li>Maximum 5 MB file size</li>
          <li>
            Supported columns: PHN, FirstName, LastName, DOB, Gender, Phone,
            Address, City, PostalCode
          </li>
        </ul>
      </div>
    </div>
  );
}

function StepMapping({
  headers,
  mapping,
  onMappingChange,
}: {
  headers: string[];
  mapping: ColumnMapping;
  onMappingChange: (mapping: ColumnMapping) => void;
}) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Map each CSV column to the corresponding patient field. Unmapped columns
        will be skipped.
      </p>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>CSV Column</TableHead>
            <TableHead>Patient Field</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {headers.map((header) => (
            <TableRow key={header}>
              <TableCell className="font-mono text-sm">{header}</TableCell>
              <TableCell>
                <Select
                  value={mapping[header] ?? '_skip'}
                  onValueChange={(value) => {
                    onMappingChange({
                      ...mapping,
                      [header]: value === '_skip' ? null : value,
                    });
                  }}
                >
                  <SelectTrigger className="w-[200px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="_skip">
                      <span className="text-muted-foreground">-- Skip --</span>
                    </SelectItem>
                    {PATIENT_FIELDS.map((field) => (
                      <SelectItem key={field.value} value={field.value}>
                        {field.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function StepPreview({
  rows,
  mapping,
  validationResult,
  onValidate,
  isValidating,
}: {
  rows: CsvRow[];
  mapping: ColumnMapping;
  validationResult: ValidationResult | null;
  onValidate: () => void;
  isValidating: boolean;
}) {
  // Build mapped preview rows (first 10)
  const mappedFields = Object.entries(mapping)
    .filter(([, field]) => field !== null)
    .map(([csvCol, field]) => ({ csvCol, field: field! }));

  const previewRows = rows.slice(0, 10).map((row) => {
    const mapped: Record<string, string> = {};
    mappedFields.forEach(({ csvCol, field }) => {
      mapped[field] = row[csvCol] ?? '';
    });
    return mapped;
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Preview of first {Math.min(10, rows.length)} rows (
          {rows.length} total)
        </p>
        <Button onClick={onValidate} disabled={isValidating}>
          {isValidating && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          Validate All Rows
        </Button>
      </div>

      {/* Preview Table */}
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-12">#</TableHead>
              {mappedFields.map(({ field }) => (
                <TableHead key={field}>
                  {PATIENT_FIELDS.find((f) => f.value === field)?.label ?? field}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {previewRows.map((row, i) => (
              <TableRow key={i}>
                <TableCell className="text-muted-foreground">{i + 1}</TableCell>
                {mappedFields.map(({ field }) => (
                  <TableCell key={field} className="max-w-[200px] truncate text-sm">
                    {row[field] || '---'}
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {/* Validation Results */}
      {validationResult && (
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-5 w-5 text-green-600" />
                <span className="text-sm font-medium">
                  {validationResult.valid.length} valid rows
                </span>
              </div>
              {validationResult.invalid.length > 0 && (
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-amber-500" />
                  <span className="text-sm font-medium">
                    {validationResult.invalid.length} rows with errors
                  </span>
                </div>
              )}
              <span className="text-sm text-muted-foreground">
                {validationResult.total} total rows
              </span>
            </div>

            {validationResult.invalid.length > 0 && (
              <div className="mt-4 max-h-48 space-y-1 overflow-y-auto">
                {validationResult.invalid.slice(0, 20).map((item) => (
                  <p key={item.row} className="text-xs text-destructive">
                    Row {item.row}: {item.errors.join(', ')}
                  </p>
                ))}
                {validationResult.invalid.length > 20 && (
                  <p className="text-xs text-muted-foreground">
                    ...and {validationResult.invalid.length - 20} more errors
                  </p>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function StepConfirm({
  validationResult,
  isImporting,
  importResult,
}: {
  validationResult: ValidationResult | null;
  isImporting: boolean;
  importResult: { imported: number; skipped: number } | null;
}) {
  if (importResult) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <CheckCircle2 className="h-16 w-16 text-green-600" />
        <h3 className="mt-4 text-lg font-semibold">Import Complete</h3>
        <p className="mt-2 text-sm text-muted-foreground">
          Successfully imported {importResult.imported} patients.
          {importResult.skipped > 0 &&
            ` ${importResult.skipped} rows were skipped due to errors.`}
        </p>
        <Link href={ROUTES.PATIENTS}>
          <Button className="mt-6">View Patients</Button>
        </Link>
      </div>
    );
  }

  if (isImporting) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <Loader2 className="h-16 w-16 animate-spin text-primary" />
        <h3 className="mt-4 text-lg font-semibold">Importing...</h3>
        <p className="mt-2 text-sm text-muted-foreground">
          Please wait while your patients are being imported.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="rounded-lg border p-6 text-center">
        <Upload className="mx-auto h-12 w-12 text-muted-foreground/50" />
        <h3 className="mt-4 text-lg font-semibold">Ready to Import</h3>
        <p className="mt-2 text-sm text-muted-foreground">
          {validationResult
            ? `${validationResult.valid.length} valid records will be imported.`
            : 'Please validate your data before importing.'}
        </p>
        {validationResult && validationResult.invalid.length > 0 && (
          <p className="mt-1 text-sm text-amber-600">
            {validationResult.invalid.length} invalid rows will be skipped.
          </p>
        )}
      </div>
    </div>
  );
}

// ---------- Main Page ----------

const STEPS = ['Upload', 'Map Columns', 'Preview', 'Import'] as const;

export default function PatientImportPage() {
  const [step, setStep] = useState(0);
  const [headers, setHeaders] = useState<string[]>([]);
  const [rows, setRows] = useState<CsvRow[]>([]);
  const [mapping, setMapping] = useState<ColumnMapping>({});
  const [validationResult, setValidationResult] =
    useState<ValidationResult | null>(null);
  const [isValidating, setIsValidating] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [importResult, setImportResult] = useState<{
    imported: number;
    skipped: number;
  } | null>(null);

  const handleFilesParsed = useCallback(
    (parsedHeaders: string[], parsedRows: CsvRow[]) => {
      setHeaders(parsedHeaders);
      setRows(parsedRows);
      setMapping(autoDetectMapping(parsedHeaders));
      setValidationResult(null);
      setImportResult(null);
      setStep(1);
    },
    []
  );

  const handleValidate = useCallback(async () => {
    setIsValidating(true);
    try {
      const response = await api.post<{ data: ValidationResult }>(
        '/api/v1/patients/import/validate',
        { rows, mapping }
      );
      setValidationResult(response.data);
    } catch (error: any) {
      // Client-side validation fallback
      const mappedFields = Object.entries(mapping).filter(
        ([, field]) => field !== null
      );
      const valid: CsvRow[] = [];
      const invalid: Array<{ row: number; errors: string[] }> = [];

      rows.forEach((row, index) => {
        const errors: string[] = [];
        const mapped: Record<string, string> = {};
        mappedFields.forEach(([csvCol, field]) => {
          mapped[field!] = row[csvCol] ?? '';
        });

        if (!mapped.first_name) errors.push('First name is required');
        if (!mapped.last_name) errors.push('Last name is required');
        if (!mapped.date_of_birth) errors.push('Date of birth is required');

        if (errors.length > 0) {
          invalid.push({ row: index + 2, errors });
        } else {
          valid.push(mapped as CsvRow);
        }
      });

      setValidationResult({ valid, invalid, total: rows.length });
    } finally {
      setIsValidating(false);
    }
  }, [rows, mapping]);

  const handleImport = useCallback(async () => {
    if (!validationResult || validationResult.valid.length === 0) {
      toast.error('No valid rows', {
        description: 'Please validate and fix errors before importing.',
      });
      return;
    }

    setIsImporting(true);
    try {
      const response = await api.post<{
        data: { imported: number; skipped: number };
      }>('/api/v1/patients/import', {
        rows: validationResult.valid,
        mapping,
      });
      setImportResult(response.data);
      toast.success('Import successful', {
        description: `${response.data.imported} patients were imported.`,
      });
    } catch (error: any) {
      toast.error('Import failed', {
        description: error?.message ?? 'An unexpected error occurred.',
      });
    } finally {
      setIsImporting(false);
    }
  }, [validationResult, mapping]);

  const canGoNext = () => {
    switch (step) {
      case 0:
        return headers.length > 0 && rows.length > 0;
      case 1: {
        const mappedFields = Object.values(mapping).filter(Boolean);
        return (
          mappedFields.includes('first_name') &&
          mappedFields.includes('last_name')
        );
      }
      case 2:
        return validationResult !== null && validationResult.valid.length > 0;
      case 3:
        return false;
      default:
        return false;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link href={ROUTES.PATIENTS}>
          <Button variant="ghost" size="icon">
            <ArrowLeft className="h-4 w-4" />
          </Button>
        </Link>
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Import Patients</h1>
          <p className="text-muted-foreground">
            Bulk import patients from a CSV file
          </p>
        </div>
      </div>

      {/* Step Indicator */}
      <div className="flex items-center gap-2">
        {STEPS.map((label, index) => (
          <React.Fragment key={label}>
            {index > 0 && (
              <div
                className={`h-px flex-1 ${
                  index <= step ? 'bg-primary' : 'bg-border'
                }`}
              />
            )}
            <div className="flex items-center gap-2">
              <div
                className={`flex h-8 w-8 items-center justify-center rounded-full text-xs font-medium ${
                  index < step
                    ? 'bg-primary text-primary-foreground'
                    : index === step
                      ? 'border-2 border-primary text-primary'
                      : 'border border-border text-muted-foreground'
                }`}
              >
                {index < step ? (
                  <CheckCircle2 className="h-4 w-4" />
                ) : (
                  index + 1
                )}
              </div>
              <span
                className={`hidden text-sm sm:inline ${
                  index === step
                    ? 'font-medium'
                    : 'text-muted-foreground'
                }`}
              >
                {label}
              </span>
            </div>
          </React.Fragment>
        ))}
      </div>

      {/* Step Content */}
      <Card>
        <CardHeader>
          <CardTitle>{STEPS[step]}</CardTitle>
          <CardDescription>
            {step === 0 && 'Upload a CSV file containing your patient data.'}
            {step === 1 && 'Map CSV columns to patient fields.'}
            {step === 2 && 'Preview and validate the mapped data before importing.'}
            {step === 3 && 'Review and confirm the import.'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {step === 0 && <StepUpload onFilesParsed={handleFilesParsed} />}
          {step === 1 && (
            <StepMapping
              headers={headers}
              mapping={mapping}
              onMappingChange={setMapping}
            />
          )}
          {step === 2 && (
            <StepPreview
              rows={rows}
              mapping={mapping}
              validationResult={validationResult}
              onValidate={handleValidate}
              isValidating={isValidating}
            />
          )}
          {step === 3 && (
            <StepConfirm
              validationResult={validationResult}
              isImporting={isImporting}
              importResult={importResult}
            />
          )}
        </CardContent>
      </Card>

      {/* Navigation */}
      {!importResult && (
        <div className="flex justify-between">
          <Button
            variant="outline"
            onClick={() => setStep((s) => Math.max(0, s - 1))}
            disabled={step === 0 || isImporting}
          >
            <ArrowLeft className="mr-2 h-4 w-4" />
            Previous
          </Button>

          {step < 3 ? (
            <Button
              onClick={() => setStep((s) => s + 1)}
              disabled={!canGoNext()}
            >
              Next
              <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
          ) : (
            <Button
              onClick={handleImport}
              disabled={
                isImporting ||
                !validationResult ||
                validationResult.valid.length === 0
              }
            >
              {isImporting && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              {isImporting
                ? 'Importing...'
                : `Import ${validationResult?.valid.length ?? 0} Patients`}
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
