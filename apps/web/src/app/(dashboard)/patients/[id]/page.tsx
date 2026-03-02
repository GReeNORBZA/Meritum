'use client';

import { useParams } from 'next/navigation';
import Link from 'next/link';
import { usePatient, usePatientEligibility, useDeletePatient } from '@/hooks/api/use-patients';
import { ROUTES } from '@/config/routes';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import {
  ArrowLeft,
  Edit,
  Trash2,
  Phone,
  Mail,
  MapPin,
  Shield,
  ShieldCheck,
  ShieldX,
  Clock,
  FileText,
  UserRound,
} from 'lucide-react';
import { formatPhn } from '@/lib/formatters/phn';
import { formatDate, formatDateTime, formatRelative } from '@/lib/formatters/date';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';
import { api } from '@/lib/api/client';
import { useQuery } from '@tanstack/react-query';
import { queryKeys } from '@/lib/api/query-keys';
import type { PaginatedResponse } from '@/lib/api/client';

// ---------- Types ----------

interface Claim {
  id: string;
  service_date: string;
  hsc_code: string;
  status: string;
  billed_amount: number;
  paid_amount: number | null;
  created_at: string;
}

// ---------- Info Item ----------

function InfoItem({
  icon: Icon,
  label,
  value,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-3">
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-muted">
        <Icon className="h-4 w-4 text-muted-foreground" />
      </div>
      <div>
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className="text-sm font-medium">{value || '---'}</p>
      </div>
    </div>
  );
}

// ---------- Eligibility Badge ----------

function EligibilityBadge({ patientId }: { patientId: string }) {
  const { data, isLoading, isError } = usePatientEligibility(patientId);
  const eligibility = data?.data;

  if (isLoading) {
    return <Skeleton className="h-5 w-20" />;
  }

  if (isError || !eligibility) {
    return (
      <Badge variant="outline" className="gap-1">
        <Shield className="h-3 w-3" />
        Not verified
      </Badge>
    );
  }

  if (eligibility.is_eligible) {
    return (
      <Badge variant="default" className="gap-1 bg-green-600">
        <ShieldCheck className="h-3 w-3" />
        Eligible
      </Badge>
    );
  }

  return (
    <Badge variant="destructive" className="gap-1">
      <ShieldX className="h-3 w-3" />
      Not eligible
    </Badge>
  );
}

// ---------- Claims Tab ----------

function ClaimsTab({ patientId }: { patientId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: [...queryKeys.claims.all, 'patient', patientId],
    queryFn: () =>
      api.get<PaginatedResponse<Claim>>('/api/v1/claims', {
        params: { patient_id: patientId, page: 1, page_size: 20 },
      }),
    enabled: !!patientId,
  });

  const claims = data?.data ?? [];

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-14 w-full" />
        ))}
      </div>
    );
  }

  if (claims.length === 0) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12">
          <FileText className="h-12 w-12 text-muted-foreground/50" />
          <p className="mt-4 text-sm text-muted-foreground">
            No claims found for this patient.
          </p>
          <Link href={ROUTES.CLAIMS_NEW}>
            <Button variant="outline" className="mt-4">
              Create Claim
            </Button>
          </Link>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-2">
      {claims.map((claim) => (
        <Link
          key={claim.id}
          href={ROUTES.CLAIM_DETAIL(claim.id)}
          className="flex items-center justify-between rounded-lg border p-4 transition-colors hover:bg-accent"
        >
          <div className="flex items-center gap-4">
            <div>
              <p className="text-sm font-medium">{claim.hsc_code}</p>
              <p className="text-xs text-muted-foreground">
                {formatDate(claim.service_date)}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className="text-sm font-medium">
                ${(claim.billed_amount / 100).toFixed(2)}
              </p>
              {claim.paid_amount != null && (
                <p className="text-xs text-muted-foreground">
                  Paid: ${(claim.paid_amount / 100).toFixed(2)}
                </p>
              )}
            </div>
            <Badge
              variant={
                claim.status === 'PAID'
                  ? 'default'
                  : claim.status === 'REJECTED'
                    ? 'destructive'
                    : 'secondary'
              }
            >
              {claim.status}
            </Badge>
          </div>
        </Link>
      ))}
    </div>
  );
}

// ---------- History Tab ----------

function HistoryTab({ patientId }: { patientId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: [...queryKeys.patients.detail(patientId), 'history'],
    queryFn: () =>
      api.get<{
        data: Array<{
          id: string;
          action: string;
          details: string | null;
          created_at: string;
          actor_name: string | null;
        }>;
      }>(`/api/v1/patients/${patientId}/history`, {
        params: { page: 1, page_size: 50 },
      }),
    enabled: !!patientId,
  });

  const history = data?.data ?? [];

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full" />
        ))}
      </div>
    );
  }

  if (history.length === 0) {
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12">
          <Clock className="h-12 w-12 text-muted-foreground/50" />
          <p className="mt-4 text-sm text-muted-foreground">
            No history records found.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-2">
      {history.map((entry) => (
        <div
          key={entry.id}
          className="flex items-start gap-3 rounded-lg border p-4"
        >
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted">
            <Clock className="h-4 w-4 text-muted-foreground" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium">{entry.action}</p>
            {entry.details && (
              <p className="mt-1 text-xs text-muted-foreground">
                {entry.details}
              </p>
            )}
            <p className="mt-1 text-xs text-muted-foreground">
              {entry.actor_name ? `${entry.actor_name} - ` : ''}
              {formatDateTime(entry.created_at)}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------- Main Page ----------

export default function PatientDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const patientId = params.id;

  const { data, isLoading, isError } = usePatient(patientId);
  const deletePatient = useDeletePatient();
  const patient = data?.data;

  const handleDelete = async () => {
    try {
      await deletePatient.mutateAsync(patientId);
      toast.success('Patient deleted', {
        description: 'The patient record has been removed.',
      });
      router.push(ROUTES.PATIENTS);
    } catch (error: any) {
      toast.error('Failed to delete patient', {
        description: error?.message ?? 'An unexpected error occurred.',
      });
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Skeleton className="h-10 w-10 rounded" />
          <div className="space-y-2">
            <Skeleton className="h-8 w-64" />
            <Skeleton className="h-4 w-32" />
          </div>
        </div>
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (isError || !patient) {
    return (
      <div className="flex flex-col items-center justify-center py-24">
        <UserRound className="h-16 w-16 text-muted-foreground/50" />
        <h2 className="mt-4 text-lg font-semibold">Patient not found</h2>
        <p className="mt-2 text-sm text-muted-foreground">
          The patient record you are looking for does not exist or has been removed.
        </p>
        <Link href={ROUTES.PATIENTS}>
          <Button variant="outline" className="mt-4">
            Back to Patients
          </Button>
        </Link>
      </div>
    );
  }

  const genderLabel =
    patient.gender === 'M' ? 'Male' : patient.gender === 'F' ? 'Female' : 'Other';

  const fullAddress = [
    patient.address_line_1,
    patient.address_line_2,
    patient.city,
    patient.province,
    patient.postal_code,
  ]
    .filter(Boolean)
    .join(', ');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link href={ROUTES.PATIENTS}>
            <Button variant="ghost" size="icon">
              <ArrowLeft className="h-4 w-4" />
            </Button>
          </Link>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-3xl font-bold tracking-tight">
                {patient.last_name}, {patient.first_name}
                {patient.middle_name ? ` ${patient.middle_name}` : ''}
              </h1>
              <EligibilityBadge patientId={patientId} />
            </div>
            <p className="text-muted-foreground">
              {patient.phn
                ? `PHN: ${formatPhn(patient.phn)}`
                : 'No PHN on file'}
              {' | '}
              DOB: {formatDate(patient.date_of_birth)}
              {' | '}
              {genderLabel}
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <Link href={ROUTES.PATIENT_EDIT(patientId)}>
            <Button variant="outline">
              <Edit className="mr-2 h-4 w-4" />
              Edit
            </Button>
          </Link>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="outline" className="text-destructive hover:text-destructive">
                <Trash2 className="mr-2 h-4 w-4" />
                Delete
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Delete patient record?</AlertDialogTitle>
                <AlertDialogDescription>
                  This will permanently remove{' '}
                  <strong>
                    {patient.first_name} {patient.last_name}
                  </strong>{' '}
                  from the registry. This action cannot be undone. All associated
                  claims will be preserved but unlinked.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction
                  onClick={handleDelete}
                  className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                >
                  Delete Patient
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="claims">Claims</TabsTrigger>
          <TabsTrigger value="history">History</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6">
          <div className="grid gap-6 md:grid-cols-2">
            {/* Patient Info */}
            <Card>
              <CardHeader>
                <CardTitle>Patient Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <InfoItem
                  icon={UserRound}
                  label="Full Name"
                  value={`${patient.first_name}${patient.middle_name ? ` ${patient.middle_name}` : ''} ${patient.last_name}`}
                />
                <InfoItem
                  icon={FileText}
                  label="PHN"
                  value={
                    patient.phn ? (
                      <span className="font-mono">
                        {formatPhn(patient.phn)}{' '}
                        <Badge variant="outline" className="ml-1">
                          {patient.phn_province}
                        </Badge>
                      </span>
                    ) : (
                      'Not on file'
                    )
                  }
                />
                <InfoItem
                  icon={Clock}
                  label="Date of Birth"
                  value={formatDate(patient.date_of_birth)}
                />
                <InfoItem
                  icon={UserRound}
                  label="Gender"
                  value={genderLabel}
                />
              </CardContent>
            </Card>

            {/* Contact Info */}
            <Card>
              <CardHeader>
                <CardTitle>Contact Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <InfoItem
                  icon={Phone}
                  label="Phone"
                  value={patient.phone}
                />
                <InfoItem
                  icon={Mail}
                  label="Email"
                  value={patient.email}
                />
                <InfoItem
                  icon={MapPin}
                  label="Address"
                  value={fullAddress || null}
                />
              </CardContent>
            </Card>
          </div>

          {/* Notes */}
          {patient.notes && (
            <Card>
              <CardHeader>
                <CardTitle>Notes</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="whitespace-pre-wrap text-sm text-muted-foreground">
                  {patient.notes}
                </p>
              </CardContent>
            </Card>
          )}

          {/* Metadata */}
          <Card>
            <CardHeader>
              <CardTitle>Record Information</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 sm:grid-cols-3">
                <div>
                  <p className="text-xs text-muted-foreground">Created</p>
                  <p className="text-sm">
                    {formatDateTime(patient.created_at)}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Last Updated</p>
                  <p className="text-sm">
                    {formatRelative(patient.updated_at)}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Last Visit</p>
                  <p className="text-sm">
                    {patient.last_visit_date
                      ? formatDate(patient.last_visit_date)
                      : 'No visits'}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Claims Tab */}
        <TabsContent value="claims">
          <ClaimsTab patientId={patientId} />
        </TabsContent>

        {/* History Tab */}
        <TabsContent value="history">
          <HistoryTab patientId={patientId} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
