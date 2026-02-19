// ============================================================================
// Domain 11: Onboarding — Constants
// ============================================================================

// --- Onboarding Step ---

export const OnboardingStep = {
  PROFESSIONAL_IDENTITY: 1,
  SPECIALTY_TYPE: 2,
  BUSINESS_ARRANGEMENT: 3,
  PRACTICE_LOCATION: 4,
  WCB_CONFIGURATION: 5,
  SUBMISSION_PREFERENCES: 6,
  IMA_ACKNOWLEDGEMENT: 7,
} as const;

export type OnboardingStep =
  (typeof OnboardingStep)[keyof typeof OnboardingStep];

// --- Required Steps ---

export const REQUIRED_ONBOARDING_STEPS: ReadonlySet<OnboardingStep> = new Set([
  OnboardingStep.PROFESSIONAL_IDENTITY,
  OnboardingStep.SPECIALTY_TYPE,
  OnboardingStep.BUSINESS_ARRANGEMENT,
  OnboardingStep.PRACTICE_LOCATION,
  OnboardingStep.IMA_ACKNOWLEDGEMENT,
]);

// --- BA Linkage Status ---

export const BALinkageStatus = {
  PENDING: 'PENDING',
  ACTIVE: 'ACTIVE',
  INACTIVE: 'INACTIVE',
} as const;

export type BALinkageStatus =
  (typeof BALinkageStatus)[keyof typeof BALinkageStatus];

// --- IMA Template Version ---

export const IMA_TEMPLATE_VERSION = '1.0.0' as const;

// --- Guided Tour Stops ---

export const GuidedTourStop = {
  DASHBOARD_OVERVIEW: 'DASHBOARD_OVERVIEW',
  CREATE_CLAIM: 'CREATE_CLAIM',
  AI_COACH: 'AI_COACH',
  THURSDAY_BATCH: 'THURSDAY_BATCH',
  NOTIFICATIONS: 'NOTIFICATIONS',
  HELP: 'HELP',
} as const;

export type GuidedTourStop =
  (typeof GuidedTourStop)[keyof typeof GuidedTourStop];

// --- Onboarding Audit Action Identifiers ---

export const OnboardingAuditAction = {
  STARTED: 'onboarding.started',
  STEP_COMPLETED: 'onboarding.step_completed',
  COMPLETED: 'onboarding.completed',
  IMA_ACKNOWLEDGED: 'onboarding.ima_acknowledged',
  IMA_DOWNLOADED: 'onboarding.ima_downloaded',
  AHC11236_DOWNLOADED: 'onboarding.ahc11236_downloaded',
  PIA_DOWNLOADED: 'onboarding.pia_downloaded',
  PATIENT_IMPORT_COMPLETED: 'onboarding.patient_import_completed',
  GUIDED_TOUR_COMPLETED: 'onboarding.guided_tour_completed',
  GUIDED_TOUR_DISMISSED: 'onboarding.guided_tour_dismissed',
  BA_STATUS_UPDATED: 'onboarding.ba_status_updated',
} as const;

export type OnboardingAuditAction =
  (typeof OnboardingAuditAction)[keyof typeof OnboardingAuditAction];
