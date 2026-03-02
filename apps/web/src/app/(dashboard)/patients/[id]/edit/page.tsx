'use client';

import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { usePatient, useUpdatePatient } from '@/hooks/api/use-patients';
import { ROUTES } from '@/config/routes';
import { PatientForm } from '@/components/domain/patients/patient-form';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { ArrowLeft, UserRound } from 'lucide-react';
import { toast } from 'sonner';
import type { UpdatePatient } from '@meritum/shared';

export default function EditPatientPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const patientId = params.id;

  const { data, isLoading, isError } = usePatient(patientId);
  const updatePatient = useUpdatePatient();
  const patient = data?.data;

  const handleSubmit = async (formData: UpdatePatient) => {
    try {
      await updatePatient.mutateAsync({ id: patientId, data: formData });
      toast.success('Patient updated', {
        description: 'The patient record has been saved.',
      });
      router.push(ROUTES.PATIENT_DETAIL(patientId));
    } catch (error: any) {
      toast.error('Failed to update patient', {
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
        <div className="max-w-3xl space-y-6">
          <Skeleton className="h-64 w-full" />
          <Skeleton className="h-32 w-full" />
          <Skeleton className="h-48 w-full" />
        </div>
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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link href={ROUTES.PATIENT_DETAIL(patientId)}>
          <Button variant="ghost" size="icon">
            <ArrowLeft className="h-4 w-4" />
          </Button>
        </Link>
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Edit Patient</h1>
          <p className="text-muted-foreground">
            {patient.last_name}, {patient.first_name}
            {patient.middle_name ? ` ${patient.middle_name}` : ''}
          </p>
        </div>
      </div>

      {/* Form */}
      <div className="max-w-3xl">
        <PatientForm
          mode="edit"
          initialValues={patient}
          onSubmit={handleSubmit as any}
          isSubmitting={updatePatient.isPending}
        />
      </div>
    </div>
  );
}
