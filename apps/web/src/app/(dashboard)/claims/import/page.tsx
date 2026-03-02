'use client';

import * as React from 'react';
import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
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
import { Progress } from '@/components/ui/progress';
import { FileUpload } from '@/components/forms/file-upload';
import { api } from '@/lib/api/client';
import type { ApiResponse } from '@/lib/api/client';
import { ROUTES } from '@/config/routes';
import {
  Upload,
  ArrowRight,
  ArrowLeft,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Loader2,
  FileText,
  Columns3,
  Eye,
  Check,
} from 'lucide-react';

// ---------- Types ----------

interface FieldMapping {
  source_column: string;
  target_field: string;
}

interface PreviewRow {
  row_number: number;
  data: Record<string, string>;
  valid: boolean;
  errors?: string[];
}

interface ImportResult {
  id: string;
  total_rows: number;
  valid_rows: number;
  invalid_rows: number;
  claims_created: number;
}

const TARGET_FIELDS = [
  { value: '', label: '-- Skip --' },
  { value: 'patient_phn', label: 'Patient PHN' },
  { value: 'patient_first_name', label: 'Patient First Name' },
  { value: 'patient_last_name', label: 'Patient Last Name' },
  { value: 'date_of_service', label: 'Date of Service' },
  { value: 'health_service_code', label: 'HSC Code' },
  { value: 'diagnostic_code', label: 'Diagnostic Code' },
  { value: 'modifier', label: 'Modifier' },
  { value: 'calls', label: 'Calls' },
  { value: 'referring_provider', label: 'Referring Provider' },
  { value: 'encounter_type', label: 'Encounter Type' },
  { value: 'functional_centre', label: 'Functional Centre' },
] as const;

// ---------- Step Indicator ----------

function StepIndicator({ currentStep }: { currentStep: number }) {
  const steps = [
    { number: 1, label: 'Upload', icon: Upload },
    { number: 2, label: 'Map Fields', icon: Columns3 },
    { number: 3, label: 'Preview', icon: Eye },
    { number: 4, label: 'Confirm', icon: Check },
  ];

  return (
    <div className="flex items-center gap-2">
      {steps.map((step, index) => {
        const Icon = step.icon;
        const isCompleted = currentStep > step.number;
        const isCurrent = currentStep === step.number;

        return (
          <React.Fragment key={step.number}>
            <div className="flex items-center gap-2">
              <div
                className={`flex h-8 w-8 items-center justify-center rounded-full text-sm font-medium ${
                  isCompleted
                    ? 'bg-primary text-primary-foreground'
                    : isCurrent
                      ? 'bg-primary text-primary-foreground ring-2 ring-primary ring-offset-2'
                      : 'bg-muted text-muted-foreground'
                }`}
              >
                {isCompleted ? (
                  <CheckCircle className="h-4 w-4" />
                ) : (
                  <Icon className="h-4 w-4" />
                )}
              </div>
              <span
                className={`hidden text-sm sm:inline ${
                  isCurrent ? 'font-medium' : 'text-muted-foreground'
                }`}
              >
                {step.label}
              </span>
            </div>
            {index < steps.length - 1 && (
              <div
                className={`h-0.5 w-8 ${
                  isCompleted ? 'bg-primary' : 'bg-muted'
                }`}
              />
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}

// ---------- Step 1: Upload ----------

function UploadStep({
  onUpload,
}: {
  onUpload: (file: File) => void;
}) {
  const [files, setFiles] = React.useState<File[]>([]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Upload className="h-5 w-5" />
          Upload EMR Export File
        </CardTitle>
        <CardDescription>
          Upload a CSV or Excel file exported from your EMR system.
          Supported formats: .csv, .xlsx, .xls
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <FileUpload
          accept=".csv,.xlsx,.xls"
          maxSize={20 * 1024 * 1024}
          maxFiles={1}
          onUpload={(uploaded) => setFiles(uploaded)}
        />

        <div className="flex justify-end">
          <Button
            disabled={files.length === 0}
            onClick={() => files[0] && onUpload(files[0])}
          >
            Continue
            <ArrowRight className="ml-2 h-4 w-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ---------- Step 2: Map Fields ----------

function MapFieldsStep({
  sourceColumns,
  mappings,
  onMappingsChange,
  onBack,
  onNext,
}: {
  sourceColumns: string[];
  mappings: FieldMapping[];
  onMappingsChange: (mappings: FieldMapping[]) => void;
  onBack: () => void;
  onNext: () => void;
}) {
  const updateMapping = (index: number, targetField: string) => {
    const updated = [...mappings];
    updated[index] = { ...updated[index], target_field: targetField };
    onMappingsChange(updated);
  };

  const requiredMapped = mappings.some(
    (m) => m.target_field === 'patient_phn'
  ) && mappings.some(
    (m) => m.target_field === 'date_of_service'
  ) && mappings.some(
    (m) => m.target_field === 'health_service_code'
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Columns3 className="h-5 w-5" />
          Map Fields
        </CardTitle>
        <CardDescription>
          Map each column from your file to the corresponding claim field.
          Required fields: Patient PHN, Date of Service, HSC Code.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Source Column</TableHead>
                <TableHead>Target Field</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sourceColumns.map((col, index) => (
                <TableRow key={col}>
                  <TableCell className="font-mono text-sm">{col}</TableCell>
                  <TableCell>
                    <Select
                      value={mappings[index]?.target_field || ''}
                      onValueChange={(val) => updateMapping(index, val)}
                    >
                      <SelectTrigger className="w-[220px]">
                        <SelectValue placeholder="-- Skip --" />
                      </SelectTrigger>
                      <SelectContent>
                        {TARGET_FIELDS.map((tf) => (
                          <SelectItem key={tf.value} value={tf.value}>
                            {tf.label}
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

        {!requiredMapped && (
          <div className="flex items-center gap-2 text-sm text-yellow-700 dark:text-yellow-400">
            <AlertTriangle className="h-4 w-4" />
            Map all required fields (Patient PHN, Date of Service, HSC Code) to continue.
          </div>
        )}

        <div className="flex justify-between">
          <Button variant="outline" onClick={onBack}>
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back
          </Button>
          <Button onClick={onNext} disabled={!requiredMapped}>
            Preview
            <ArrowRight className="ml-2 h-4 w-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ---------- Step 3: Preview ----------

function PreviewStep({
  previewRows,
  totalRows,
  validRows,
  invalidRows,
  isLoading,
  onBack,
  onConfirm,
}: {
  previewRows: PreviewRow[];
  totalRows: number;
  validRows: number;
  invalidRows: number;
  isLoading: boolean;
  onBack: () => void;
  onConfirm: () => void;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Eye className="h-5 w-5" />
          Preview & Validate
        </CardTitle>
        <CardDescription>
          Review the parsed data before importing.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Summary */}
        <div className="grid grid-cols-3 gap-4">
          <div className="rounded-md border p-3 text-center">
            <p className="text-2xl font-bold">{totalRows}</p>
            <p className="text-xs text-muted-foreground">Total Rows</p>
          </div>
          <div className="rounded-md border border-green-200 bg-green-50 p-3 text-center dark:border-green-900 dark:bg-green-950">
            <p className="text-2xl font-bold text-green-700 dark:text-green-400">
              {validRows}
            </p>
            <p className="text-xs text-muted-foreground">Valid</p>
          </div>
          <div className="rounded-md border border-red-200 bg-red-50 p-3 text-center dark:border-red-900 dark:bg-red-950">
            <p className="text-2xl font-bold text-red-700 dark:text-red-400">
              {invalidRows}
            </p>
            <p className="text-xs text-muted-foreground">Invalid</p>
          </div>
        </div>

        {/* Preview Rows */}
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            <span className="ml-2 text-muted-foreground">
              Validating data...
            </span>
          </div>
        ) : (
          <div className="max-h-[400px] overflow-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12">Row</TableHead>
                  <TableHead className="w-12">Status</TableHead>
                  {previewRows[0] &&
                    Object.keys(previewRows[0].data).map((key) => (
                      <TableHead key={key}>{key}</TableHead>
                    ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {previewRows.map((row) => (
                  <TableRow
                    key={row.row_number}
                    className={!row.valid ? 'bg-destructive/5' : ''}
                  >
                    <TableCell className="font-mono text-xs">
                      {row.row_number}
                    </TableCell>
                    <TableCell>
                      {row.valid ? (
                        <CheckCircle className="h-4 w-4 text-green-600" />
                      ) : (
                        <XCircle className="h-4 w-4 text-destructive" />
                      )}
                    </TableCell>
                    {Object.values(row.data).map((val, i) => (
                      <TableCell key={i} className="text-sm">
                        {val}
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}

        <div className="flex justify-between">
          <Button variant="outline" onClick={onBack}>
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back
          </Button>
          <Button onClick={onConfirm} disabled={isLoading || validRows === 0}>
            Confirm Import ({validRows} claims)
            <ArrowRight className="ml-2 h-4 w-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ---------- Step 4: Confirm ----------

function ConfirmStep({
  result,
  isLoading,
}: {
  result: ImportResult | null;
  isLoading: boolean;
}) {
  const router = useRouter();

  if (isLoading) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
          <p className="mt-4 text-lg font-medium">Importing claims...</p>
          <p className="text-sm text-muted-foreground">
            This may take a moment.
          </p>
          <Progress value={66} className="mt-4 w-64" />
        </CardContent>
      </Card>
    );
  }

  if (!result) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-green-700 dark:text-green-400">
          <CheckCircle className="h-5 w-5" />
          Import Complete
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <div className="rounded-md border p-3 text-center">
            <p className="text-2xl font-bold">{result.total_rows}</p>
            <p className="text-xs text-muted-foreground">Total Rows</p>
          </div>
          <div className="rounded-md border p-3 text-center">
            <p className="text-2xl font-bold text-green-600">
              {result.claims_created}
            </p>
            <p className="text-xs text-muted-foreground">Claims Created</p>
          </div>
          <div className="rounded-md border p-3 text-center">
            <p className="text-2xl font-bold">{result.valid_rows}</p>
            <p className="text-xs text-muted-foreground">Valid Rows</p>
          </div>
          <div className="rounded-md border p-3 text-center">
            <p className="text-2xl font-bold text-destructive">
              {result.invalid_rows}
            </p>
            <p className="text-xs text-muted-foreground">Skipped</p>
          </div>
        </div>

        <div className="flex justify-end gap-2">
          <Button
            variant="outline"
            onClick={() => router.push(ROUTES.CLAIMS_IMPORT)}
          >
            Import More
          </Button>
          <Button onClick={() => router.push(ROUTES.CLAIMS)}>
            View Claims
            <ArrowRight className="ml-2 h-4 w-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ---------- Main Page ----------

export default function ClaimImportPage() {
  const [step, setStep] = React.useState(1);
  const [uploadedFile, setUploadedFile] = React.useState<File | null>(null);
  const [sourceColumns, setSourceColumns] = React.useState<string[]>([]);
  const [mappings, setMappings] = React.useState<FieldMapping[]>([]);
  const [previewRows, setPreviewRows] = React.useState<PreviewRow[]>([]);
  const [totalRows, setTotalRows] = React.useState(0);
  const [validRows, setValidRows] = React.useState(0);
  const [invalidRows, setInvalidRows] = React.useState(0);
  const [importResult, setImportResult] = React.useState<ImportResult | null>(
    null
  );
  const [isProcessing, setIsProcessing] = React.useState(false);
  const [importBatchId, setImportBatchId] = React.useState<string | null>(null);

  const handleUpload = async (file: File) => {
    setUploadedFile(file);
    setIsProcessing(true);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const res = await api.post<
        ApiResponse<{
          id: string;
          columns: string[];
          row_count: number;
          preview: PreviewRow[];
        }>
      >('/api/v1/claims/import', formData);

      const data = res.data;
      setImportBatchId(data.id);
      setSourceColumns(data.columns);
      setTotalRows(data.row_count);

      // Initialize mappings
      setMappings(
        data.columns.map((col) => ({
          source_column: col,
          target_field: '',
        }))
      );

      setStep(2);
    } catch (err) {
      // Reset on error
      console.error('Upload failed:', err);
    } finally {
      setIsProcessing(false);
    }
  };

  const handlePreview = async () => {
    if (!importBatchId) return;
    setIsProcessing(true);

    try {
      const activeMappings = mappings.filter((m) => m.target_field);
      const res = await api.post<
        ApiResponse<{
          preview: PreviewRow[];
          total: number;
          valid: number;
          invalid: number;
        }>
      >(`/api/v1/claims/import/${importBatchId}/preview`, {
        mappings: activeMappings,
      });

      setPreviewRows(res.data.preview);
      setTotalRows(res.data.total);
      setValidRows(res.data.valid);
      setInvalidRows(res.data.invalid);
      setStep(3);
    } catch (err) {
      console.error('Preview failed:', err);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleConfirm = async () => {
    if (!importBatchId) return;
    setStep(4);
    setIsProcessing(true);

    try {
      const res = await api.post<ApiResponse<ImportResult>>(
        `/api/v1/claims/import/${importBatchId}/commit`
      );
      setImportResult(res.data);
    } catch (err) {
      console.error('Import failed:', err);
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">EMR Import</h1>
        <p className="text-muted-foreground">
          Import claims from your EMR system export file
        </p>
      </div>

      {/* Step Indicator */}
      <StepIndicator currentStep={step} />

      {/* Step Content */}
      {step === 1 && <UploadStep onUpload={handleUpload} />}

      {step === 2 && (
        <MapFieldsStep
          sourceColumns={sourceColumns}
          mappings={mappings}
          onMappingsChange={setMappings}
          onBack={() => setStep(1)}
          onNext={handlePreview}
        />
      )}

      {step === 3 && (
        <PreviewStep
          previewRows={previewRows}
          totalRows={totalRows}
          validRows={validRows}
          invalidRows={invalidRows}
          isLoading={isProcessing}
          onBack={() => setStep(2)}
          onConfirm={handleConfirm}
        />
      )}

      {step === 4 && (
        <ConfirmStep result={importResult} isLoading={isProcessing} />
      )}
    </div>
  );
}
