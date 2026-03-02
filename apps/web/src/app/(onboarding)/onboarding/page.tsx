'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/query-keys';
import { ROUTES } from '@/config/routes';
import { Progress } from '@/components/ui/progress';
import { Loader2 } from 'lucide-react';
import { StepProfessionalIdentity } from '@/components/domain/onboarding/step-professional-identity';
import { StepSpecialtyType } from '@/components/domain/onboarding/step-specialty-type';
import { StepBusinessArrangement } from '@/components/domain/onboarding/step-business-arrangement';
import { StepPracticeLocation } from '@/components/domain/onboarding/step-practice-location';
import { StepWcbConfig } from '@/components/domain/onboarding/step-wcb-config';
import { StepSubmissionPreferences } from '@/components/domain/onboarding/step-submission-preferences';
import { StepImaAcknowledgement } from '@/components/domain/onboarding/step-ima-acknowledgement';

const STEP_TITLES = [
  'Professional Identity',
  'Specialty & Type',
  'Business Arrangement',
  'Practice Location',
  'WCB Configuration',
  'Submission Preferences',
  'IMA Acknowledgement',
];

const TOTAL_STEPS = 7;

interface OnboardingProgress {
  current_step: number;
  steps_completed: Record<string, boolean>;
}

export default function OnboardingPage() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [currentStep, setCurrentStep] = useState(1);

  const { data: progress, isLoading } = useQuery({
    queryKey: queryKeys.onboarding.progress(),
    queryFn: () => api.get<{ data: OnboardingProgress }>('/api/v1/onboarding/progress'),
  });

  useEffect(() => {
    if (progress?.data?.current_step) {
      setCurrentStep(progress.data.current_step);
    }
  }, [progress]);

  const completeStep = useMutation({
    mutationFn: (data: { step: number; payload: Record<string, unknown> }) =>
      api.post(`/api/v1/onboarding/steps/${data.step}`, data.payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.onboarding.progress() });
    },
  });

  const handleNext = async (payload: Record<string, unknown>) => {
    await completeStep.mutateAsync({ step: currentStep, payload });
    if (currentStep < TOTAL_STEPS) {
      setCurrentStep(currentStep + 1);
    } else {
      // Complete onboarding
      await api.post('/api/v1/onboarding/complete', {});
      router.push(ROUTES.DASHBOARD);
    }
  };

  const handleBack = () => {
    if (currentStep > 1) setCurrentStep(currentStep - 1);
  };

  const handleSkip = () => {
    if (currentStep < TOTAL_STEPS) setCurrentStep(currentStep + 1);
  };

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const progressPercent = ((currentStep - 1) / TOTAL_STEPS) * 100;
  const isOptionalStep = currentStep === 5 || currentStep === 6;

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-lg font-semibold">
            Step {currentStep} of {TOTAL_STEPS}: {STEP_TITLES[currentStep - 1]}
          </h2>
          {isOptionalStep && (
            <span className="text-xs text-muted-foreground">Optional</span>
          )}
        </div>
        <Progress value={progressPercent} className="h-2" />
      </div>

      <div>
        {currentStep === 1 && <StepProfessionalIdentity onNext={handleNext} />}
        {currentStep === 2 && <StepSpecialtyType onNext={handleNext} onBack={handleBack} />}
        {currentStep === 3 && <StepBusinessArrangement onNext={handleNext} onBack={handleBack} />}
        {currentStep === 4 && <StepPracticeLocation onNext={handleNext} onBack={handleBack} />}
        {currentStep === 5 && <StepWcbConfig onNext={handleNext} onBack={handleBack} onSkip={handleSkip} />}
        {currentStep === 6 && <StepSubmissionPreferences onNext={handleNext} onBack={handleBack} onSkip={handleSkip} />}
        {currentStep === 7 && <StepImaAcknowledgement onNext={handleNext} onBack={handleBack} />}
      </div>
    </div>
  );
}
