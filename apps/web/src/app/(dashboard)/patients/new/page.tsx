'use client';

import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { ROUTES } from '@/config/routes';
import { useCreatePatient } from '@/hooks/api/use-patients';
import { PatientForm } from '@/components/domain/patients/patient-form';
import { Button } from '@/components/ui/button';
import { ArrowLeft } from 'lucide-react';
import { toast } from 'sonner';
import type { CreatePatient } from '@meritum/shared';

export default function NewPatientPage() {
  const router = useRouter();
  const createPatient = useCreatePatient();

  const handleSubmit = async (data: CreatePatient) => {
    try {
      const response = await createPatient.mutateAsync(data);
      toast.success('Patient created', {
        description: `${data.first_name} ${data.last_name} has been added to the registry.`,
      });
      router.push(ROUTES.PATIENT_DETAIL(response.data.id));
    } catch (error: any) {
      toast.error('Failed to create patient', {
        description: error?.message ?? 'An unexpected error occurred.',
      });
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
          <h1 className="text-3xl font-bold tracking-tight">Add Patient</h1>
          <p className="text-muted-foreground">
            Register a new patient in the system
          </p>
        </div>
      </div>

      {/* Form */}
      <div className="max-w-3xl">
        <PatientForm
          mode="create"
          onSubmit={handleSubmit as any}
          isSubmitting={createPatient.isPending}
        />
      </div>
    </div>
  );
}
