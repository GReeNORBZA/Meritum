'use client';

import * as React from 'react';
import { useRouter } from 'next/navigation';
import { useForm, FormProvider } from 'react-hook-form';
import { Button } from '@/components/ui/button';
import { ROUTES } from '@/config/routes';
import { useCreateWcbClaim, useUpdateWcbClaim } from '@/hooks/api/use-wcb';
import { GeneralSection } from '@/components/domain/wcb/sections/general';
import { ClaimantSection } from '@/components/domain/wcb/sections/claimant';
import { PractitionerSection } from '@/components/domain/wcb/sections/practitioner';
import { EmployerSection } from '@/components/domain/wcb/sections/employer';
import { AccidentSection } from '@/components/domain/wcb/sections/accident';
import { InjurySection } from '@/components/domain/wcb/sections/injury';
import { TreatmentPlanSection } from '@/components/domain/wcb/sections/treatment-plan';
import { ReturnToWorkSection } from '@/components/domain/wcb/sections/return-to-work';
import { InvoiceLinesSection } from '@/components/domain/wcb/sections/invoice-lines';
import { AttachmentsSection } from '@/components/domain/wcb/sections/attachments';
import { OisFieldsSection } from '@/components/domain/wcb/sections/ois-fields';
import { Loader2, Save, Send } from 'lucide-react';

// ---------- Form Type to Section Mapping ----------
// Mirrors WCB_FORM_SECTION_MATRIX from wcb.constants.ts

const SECTION_MATRIX: Record<string, string[]> = {
  C050E: [
    'GENERAL', 'CLAIMANT', 'PRACTITIONER', 'EMPLOYER', 'ACCIDENT',
    'INJURY', 'TREATMENT_PLAN', 'RETURN_TO_WORK', 'ATTACHMENTS', 'INVOICE',
  ],
  C050S: [
    'GENERAL', 'CLAIMANT', 'PRACTITIONER', 'EMPLOYER', 'ACCIDENT',
    'INJURY', 'TREATMENT_PLAN', 'RETURN_TO_WORK', 'ATTACHMENTS', 'INVOICE', 'OIS',
  ],
  C151: [
    'GENERAL', 'CLAIMANT', 'PRACTITIONER', 'EMPLOYER', 'ACCIDENT',
    'INJURY', 'TREATMENT_PLAN', 'RETURN_TO_WORK', 'ATTACHMENTS', 'INVOICE',
  ],
  C151S: [
    'GENERAL', 'CLAIMANT', 'PRACTITIONER', 'EMPLOYER', 'ACCIDENT',
    'INJURY', 'TREATMENT_PLAN', 'RETURN_TO_WORK', 'ATTACHMENTS', 'INVOICE', 'OIS',
  ],
  C568: [
    'GENERAL', 'CLAIMANT', 'PRACTITIONER', 'ACCIDENT', 'INJURY', 'INVOICE',
  ],
  C568A: [
    'GENERAL', 'CLAIMANT', 'PRACTITIONER', 'ACCIDENT', 'INJURY',
    'TREATMENT_PLAN', 'INVOICE',
  ],
  C569: [
    'GENERAL', 'CLAIMANT', 'PRACTITIONER', 'ACCIDENT', 'INVOICE',
  ],
  C570: [
    'GENERAL', 'CLAIMANT', 'PRACTITIONER', 'ACCIDENT', 'INVOICE',
  ],
};

// ---------- Types ----------

interface WcbFormBuilderProps {
  formType: string;
  onSubmit?: (data: Record<string, unknown>) => void;
  initialValues?: Record<string, unknown>;
  claimId?: string;
  readOnly?: boolean;
}

// ---------- Default Values ----------

function getDefaultValues(
  formType: string,
  initialValues?: Record<string, unknown>
): Record<string, unknown> {
  const defaults: Record<string, unknown> = {
    form_id: formType,
    patient_id: '',
    wcb_claim_number: '',
    date_of_injury: '',
    report_completion_date: '',
    additional_comments: '',
    // Claimant
    claimant_first_name: '',
    claimant_last_name: '',
    claimant_date_of_birth: '',
    claimant_phn: '',
    claimant_phone: '',
    claimant_employer: '',
    // Practitioner
    practitioner_name: '',
    practitioner_billing_number: '',
    practitioner_role_code: '',
    practitioner_contract_id: '',
    practitioner_phone: '',
    practitioner_facility_type: '',
    // Employer
    employer_name: '',
    employer_location: '',
    employer_city: '',
    employer_province: '',
    employer_phone_number: '',
    employer_phone_ext: '',
    // Accident
    worker_job_title: '',
    injury_developed_over_time: '',
    injury_description: '',
    // Injury Assessment
    date_of_examination: '',
    symptoms: '',
    objective_findings: '',
    current_diagnosis: '',
    diagnostic_code_1: '',
    diagnostic_code_2: '',
    diagnostic_code_3: '',
    diagnosis_changed: '',
    diagnosis_changed_desc: '',
    dominant_hand: '',
    prior_conditions_flag: '',
    prior_conditions_desc: '',
    // Treatment Plan
    treatment_plan_text: '',
    narcotics_prescribed: '',
    case_conf_wcb_manager: '',
    referral_rtw_provider: '',
    // Return to Work
    missed_work_beyond_accident: '',
    patient_returned_to_work: '',
    date_returned_to_work: '',
    modified_hours: '',
    hours_capable_per_day: undefined,
    modified_duties: '',
    estimated_rtw_date: '',
    rtw_hospitalized: '',
    rtw_self_reported_pain: '',
    rtw_opioid_side_effects: '',
    rtw_other_restrictions: '',
    // Child Arrays
    injuries: [],
    prescriptions: [],
    consultations: [],
    work_restrictions: [],
    invoice_lines: [],
    attachments: [],
  };

  if (initialValues) {
    return { ...defaults, ...initialValues };
  }

  return defaults;
}

// ---------- Component ----------

function WcbFormBuilder({
  formType,
  onSubmit: onSubmitProp,
  initialValues,
  claimId,
  readOnly,
}: WcbFormBuilderProps) {
  const router = useRouter();
  const createWcbClaim = useCreateWcbClaim();
  const updateWcbClaim = useUpdateWcbClaim();

  const sections = SECTION_MATRIX[formType] || SECTION_MATRIX.C050E;

  const form = useForm({
    defaultValues: getDefaultValues(formType, initialValues) as Record<string, unknown>,
  });

  const {
    handleSubmit,
    formState: { isSubmitting },
  } = form;

  const isPending = createWcbClaim.isPending || updateWcbClaim.isPending;

  const handleSave = async (data: Record<string, unknown>) => {
    if (onSubmitProp) {
      onSubmitProp(data);
      return;
    }

    const payload = { ...data, form_id: formType };

    if (claimId) {
      await updateWcbClaim.mutateAsync({ id: claimId, data: payload });
      router.push(ROUTES.WCB_DETAIL(claimId));
    } else {
      const result = await createWcbClaim.mutateAsync(payload);
      if (result.data?.id) {
        router.push(ROUTES.WCB_DETAIL(result.data.id));
      } else {
        router.push(ROUTES.WCB);
      }
    }
  };

  const hasSection = (section: string) => sections.includes(section);
  const isOisForm = formType === 'C050S' || formType === 'C151S';

  return (
    <FormProvider {...form}>
      <form
        onSubmit={handleSubmit(handleSave)}
        className="space-y-6"
        noValidate
      >
        {/* Render sections based on form type matrix */}
        {hasSection('GENERAL') && <GeneralSection readOnly={readOnly} />}
        {hasSection('CLAIMANT') && <ClaimantSection readOnly={readOnly} />}
        {hasSection('PRACTITIONER') && <PractitionerSection readOnly={readOnly} />}
        {hasSection('EMPLOYER') && <EmployerSection readOnly={readOnly} />}
        {hasSection('ACCIDENT') && <AccidentSection readOnly={readOnly} />}
        {hasSection('INJURY') && <InjurySection readOnly={readOnly} />}
        {hasSection('TREATMENT_PLAN') && <TreatmentPlanSection readOnly={readOnly} />}
        {hasSection('RETURN_TO_WORK') && <ReturnToWorkSection readOnly={readOnly} />}
        {isOisForm && <OisFieldsSection readOnly={readOnly} />}
        {hasSection('ATTACHMENTS') && <AttachmentsSection readOnly={readOnly} />}
        {hasSection('INVOICE') && (
          <InvoiceLinesSection readOnly={readOnly} formType={formType} />
        )}

        {/* Action Buttons */}
        {!readOnly && (
          <div className="flex flex-col gap-3 sm:flex-row sm:justify-end">
            <Button
              type="button"
              variant="outline"
              onClick={() => router.push(ROUTES.WCB)}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={isSubmitting || isPending}
            >
              {isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Save className="mr-2 h-4 w-4" />
              )}
              {claimId ? 'Save Changes' : 'Save WCB Claim'}
            </Button>
          </div>
        )}

        {/* Error Display */}
        {(createWcbClaim.isError || updateWcbClaim.isError) && (
          <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
            {(createWcbClaim.error ?? updateWcbClaim.error) instanceof Error
              ? (createWcbClaim.error ?? updateWcbClaim.error)?.message
              : 'Failed to save WCB claim. Please try again.'}
          </div>
        )}
      </form>
    </FormProvider>
  );
}

export { WcbFormBuilder };
export type { WcbFormBuilderProps };
