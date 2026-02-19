// ============================================================================
// Domain 11: Onboarding — Zod Validation Schemas
// ============================================================================

import { z } from 'zod';

// ============================================================================
// Shared Sub-Schemas
// ============================================================================

// --- Address ---

export const addressSchema = z.object({
  street: z.string().min(1).max(200),
  city: z.string().min(1).max(100),
  province: z.string().length(2).default('AB'),
  postal_code: z.string().regex(/^[A-Z]\d[A-Z]\s?\d[A-Z]\d$/i),
});

export type Address = z.infer<typeof addressSchema>;

// ============================================================================
// Step Input Schemas
// ============================================================================

// --- Step 1: Professional Identity ---

export const onboardingStep1Schema = z.object({
  billing_number: z.string().regex(/^\d{5}$/),
  cpsa_number: z.string().min(1).max(20),
  legal_first_name: z.string().min(1).max(100),
  legal_last_name: z.string().min(1).max(100),
});

export type OnboardingStep1 = z.infer<typeof onboardingStep1Schema>;

// --- Step 2: Specialty & Type ---

export const onboardingStep2Schema = z.object({
  specialty_code: z.string().min(1).max(10),
  physician_type: z.enum(['gp', 'specialist', 'locum']),
});

export type OnboardingStep2 = z.infer<typeof onboardingStep2Schema>;

// --- Step 3: Business Arrangement ---

export const onboardingStep3Schema = z
  .object({
    primary_ba_number: z.string().min(1).max(20),
    is_pcpcm_enrolled: z.boolean(),
    pcpcm_ba_number: z.string().max(20).optional(),
    ffs_ba_number: z.string().max(20).optional(),
  })
  .refine(
    (data) => {
      if (data.is_pcpcm_enrolled) {
        return (
          data.pcpcm_ba_number !== undefined &&
          data.pcpcm_ba_number.length > 0 &&
          data.ffs_ba_number !== undefined &&
          data.ffs_ba_number.length > 0
        );
      }
      return true;
    },
    {
      message:
        'pcpcm_ba_number and ffs_ba_number are required when is_pcpcm_enrolled is true',
      path: ['pcpcm_ba_number'],
    },
  );

export type OnboardingStep3 = z.infer<typeof onboardingStep3Schema>;

// --- Step 4: Practice Location ---

export const onboardingStep4Schema = z.object({
  location_name: z.string().min(1).max(200),
  functional_centre_code: z.string().min(1).max(10),
  facility_number: z.string().max(20).optional(),
  address: addressSchema,
  community_code: z.string().min(1).max(10),
});

export type OnboardingStep4 = z.infer<typeof onboardingStep4Schema>;

// --- Step 5: WCB Configuration ---

export const onboardingStep5Schema = z.object({
  contract_id: z.string().min(1).max(20),
  role: z.string().min(1).max(50),
  skill_code: z.string().min(1).max(10),
});

export type OnboardingStep5 = z.infer<typeof onboardingStep5Schema>;

// --- Step 6: Submission Preferences ---

export const onboardingStep6Schema = z.object({
  ahcip_mode: z
    .enum(['auto_clean', 'require_approval'])
    .default('auto_clean'),
  wcb_mode: z
    .enum(['auto_clean', 'require_approval'])
    .default('require_approval'),
});

export type OnboardingStep6 = z.infer<typeof onboardingStep6Schema>;

// ============================================================================
// Path Parameter Schemas
// ============================================================================

// --- Step Number (path param: coerced from string) ---

export const stepNumberParamSchema = z.object({
  step_number: z.coerce.number().int().min(1).max(7),
});

export type StepNumberParam = z.infer<typeof stepNumberParamSchema>;

// ============================================================================
// IMA Acknowledgement
// ============================================================================

export const imaAcknowledgeSchema = z.object({
  document_hash: z.string().length(64),
});

export type ImaAcknowledge = z.infer<typeof imaAcknowledgeSchema>;

// ============================================================================
// Response Schemas
// ============================================================================

// --- Onboarding Progress Response ---

export const onboardingProgressResponseSchema = z.object({
  progress_id: z.string().uuid(),
  provider_id: z.string().uuid(),
  step_1_completed: z.boolean(),
  step_2_completed: z.boolean(),
  step_3_completed: z.boolean(),
  step_4_completed: z.boolean(),
  step_5_completed: z.boolean(),
  step_6_completed: z.boolean(),
  step_7_completed: z.boolean(),
  patient_import_completed: z.boolean(),
  guided_tour_completed: z.boolean(),
  guided_tour_dismissed: z.boolean(),
  started_at: z.string(),
  completed_at: z.string().nullable(),
});

export type OnboardingProgressResponse = z.infer<
  typeof onboardingProgressResponseSchema
>;
