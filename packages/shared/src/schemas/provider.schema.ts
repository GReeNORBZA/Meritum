// ============================================================================
// Domain 5: Provider Management — Zod Validation Schemas
// ============================================================================

import { z } from 'zod';
import {
  PhysicianType,
  BAType,
  BAStatus,
  DelegatePermission,
  SubmissionMode,
  HLinkAccreditationStatus,
} from '../constants/provider.constants.js';

// --- Enum Value Arrays ---

const PHYSICIAN_TYPES = [
  PhysicianType.GP,
  PhysicianType.SPECIALIST,
  PhysicianType.LOCUM,
] as const;

const BA_TYPES = [BAType.FFS, BAType.PCPCM, BAType.ARP] as const;

const BA_STATUSES = [
  BAStatus.ACTIVE,
  BAStatus.PENDING,
  BAStatus.INACTIVE,
] as const;

const DELEGATE_PERMISSION_KEYS = Object.values(DelegatePermission) as [
  (typeof DelegatePermission)[keyof typeof DelegatePermission],
  ...(typeof DelegatePermission)[keyof typeof DelegatePermission][],
];

const SUBMISSION_MODES = [
  SubmissionMode.AUTO_CLEAN,
  SubmissionMode.AUTO_ALL,
  SubmissionMode.REQUIRE_APPROVAL,
] as const;

const HLINK_ACCREDITATION_STATUSES = [
  HLinkAccreditationStatus.PENDING,
  HLinkAccreditationStatus.ACTIVE,
  HLinkAccreditationStatus.SUSPENDED,
] as const;

// ============================================================================
// Provider Profile
// ============================================================================

// --- Update Provider Profile ---

export const updateProviderSchema = z.object({
  first_name: z.string().min(1).max(50).optional(),
  last_name: z.string().min(1).max(50).optional(),
  middle_name: z.string().max(50).optional(),
  specialty_code: z.string().max(10).optional(),
  specialty_description: z.string().max(100).optional(),
  sub_specialty_code: z.string().max(10).optional(),
  physician_type: z.enum(PHYSICIAN_TYPES).optional(),
});

export type UpdateProvider = z.infer<typeof updateProviderSchema>;

// --- Complete Onboarding (no body — server validates required fields) ---

export const completeOnboardingSchema = z.object({});

export type CompleteOnboarding = z.infer<typeof completeOnboardingSchema>;

// ============================================================================
// Business Arrangements
// ============================================================================

// --- Create BA ---

export const createBaSchema = z.object({
  ba_number: z.string().min(1).max(10).regex(/^\d{1,10}$/),
  ba_type: z.enum(BA_TYPES),
  is_primary: z.boolean().optional(),
  effective_date: z.string().date().optional(),
});

export type CreateBa = z.infer<typeof createBaSchema>;

// --- Update BA ---

export const updateBaSchema = z.object({
  status: z.enum(BA_STATUSES).optional(),
  effective_date: z.string().date().optional(),
  end_date: z.string().date().optional(),
});

export type UpdateBa = z.infer<typeof updateBaSchema>;

// --- BA ID Parameter ---

export const baIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type BaIdParam = z.infer<typeof baIdParamSchema>;

// ============================================================================
// Practice Locations
// ============================================================================

// --- Create Location ---

export const createLocationSchema = z.object({
  name: z.string().min(1).max(100),
  functional_centre: z.string().min(1).max(10),
  facility_number: z.string().max(10).optional(),
  address_line_1: z.string().max(100).optional(),
  address_line_2: z.string().max(100).optional(),
  city: z.string().max(50).optional(),
  province: z.string().max(2).default('AB').optional(),
  postal_code: z.string().max(7).optional(),
  community_code: z.string().max(10).optional(),
});

export type CreateLocation = z.infer<typeof createLocationSchema>;

// --- Update Location ---

export const updateLocationSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  functional_centre: z.string().min(1).max(10).optional(),
  facility_number: z.string().max(10).optional(),
  address_line_1: z.string().max(100).optional(),
  address_line_2: z.string().max(100).optional(),
  city: z.string().max(50).optional(),
  province: z.string().max(2).optional(),
  postal_code: z.string().max(7).optional(),
  community_code: z.string().max(10).optional(),
});

export type UpdateLocation = z.infer<typeof updateLocationSchema>;

// --- Location ID Parameter ---

export const locationIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type LocationIdParam = z.infer<typeof locationIdParamSchema>;

// ============================================================================
// WCB Configuration
// ============================================================================

// --- Create WCB Config ---

export const createWcbConfigSchema = z.object({
  contract_id: z.string().min(1).max(10),
  role_code: z.string().min(1).max(10),
  skill_code: z.string().max(10).optional(),
  is_default: z.boolean().optional(),
});

export type CreateWcbConfig = z.infer<typeof createWcbConfigSchema>;

// --- Update WCB Config ---

export const updateWcbConfigSchema = z.object({
  skill_code: z.string().max(10).optional(),
  is_default: z.boolean().optional(),
});

export type UpdateWcbConfig = z.infer<typeof updateWcbConfigSchema>;

// --- WCB Config ID Parameter ---

export const wcbConfigIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type WcbConfigIdParam = z.infer<typeof wcbConfigIdParamSchema>;

// ============================================================================
// Delegate Management
// ============================================================================

// --- Invite Delegate ---

export const inviteDelegateSchema = z.object({
  email: z.string().email().max(255),
  permissions: z.array(z.enum(DELEGATE_PERMISSION_KEYS)).min(1),
});

export type InviteDelegate = z.infer<typeof inviteDelegateSchema>;

// --- Update Delegate Permissions ---

export const updateDelegatePermissionsSchema = z.object({
  permissions: z.array(z.enum(DELEGATE_PERMISSION_KEYS)).min(1),
});

export type UpdateDelegatePermissions = z.infer<typeof updateDelegatePermissionsSchema>;

// --- Delegate Relationship ID Parameter ---

export const delegateRelIdParamSchema = z.object({
  rel_id: z.string().uuid(),
});

export type DelegateRelIdParam = z.infer<typeof delegateRelIdParamSchema>;

// --- Accept Invitation ---

export const acceptInvitationSchema = z.object({
  token: z.string().min(1),
});

export type AcceptInvitation = z.infer<typeof acceptInvitationSchema>;

// --- Switch Context Parameter ---

export const switchContextParamSchema = z.object({
  provider_id: z.string().uuid(),
});

export type SwitchContextParam = z.infer<typeof switchContextParamSchema>;

// ============================================================================
// Submission Preferences
// ============================================================================

// --- Update Submission Preferences ---

export const updateSubmissionPreferencesSchema = z.object({
  ahcip_submission_mode: z.enum(SUBMISSION_MODES).optional(),
  wcb_submission_mode: z.enum(SUBMISSION_MODES).optional(),
  batch_review_reminder: z.boolean().optional(),
  deadline_reminder_days: z.number().int().min(1).max(30).optional(),
});

export type UpdateSubmissionPreferences = z.infer<typeof updateSubmissionPreferencesSchema>;

// ============================================================================
// H-Link Configuration
// ============================================================================

// --- Update H-Link Config ---

export const updateHlinkConfigSchema = z.object({
  submitter_prefix: z.string().min(1).max(10).optional(),
  accreditation_status: z.enum(HLINK_ACCREDITATION_STATUSES).optional(),
});

export type UpdateHlinkConfig = z.infer<typeof updateHlinkConfigSchema>;

// ============================================================================
// Internal Provider Context API
// ============================================================================

// --- Provider ID Parameter ---

export const providerIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type ProviderIdParam = z.infer<typeof providerIdParamSchema>;

// --- BA for Claim Query ---

export const baForClaimQuerySchema = z.object({
  claim_type: z.enum(['AHCIP', 'WCB']),
  hsc_code: z.string().optional(),
});

export type BaForClaimQuery = z.infer<typeof baForClaimQuerySchema>;

// --- WCB Config for Form Query ---

export const wcbConfigForFormQuerySchema = z.object({
  form_id: z.string().min(1),
});

export type WcbConfigForFormQuery = z.infer<typeof wcbConfigForFormQuerySchema>;

// ============================================================================
// Provider Context Response Type (consumed by Domain 4 — Claim Lifecycle)
// ============================================================================

export interface ProviderContext {
  provider_id: string;
  billing_number: string;
  specialty_code: string;
  physician_type: string;
  bas: Array<{
    ba_id: string;
    ba_number: string;
    ba_type: string;
    is_primary: boolean;
    status: string;
  }>;
  default_location: {
    location_id: string;
    name: string;
    functional_centre: string;
    facility_number: string | null;
  } | null;
  all_locations: Array<{
    location_id: string;
    name: string;
    functional_centre: string;
    is_active: boolean;
  }>;
  pcpcm_enrolled: boolean;
  pcpcm_ba_number: string | null;
  ffs_ba_number: string | null;
  wcb_configs: Array<{
    wcb_config_id: string;
    contract_id: string;
    role_code: string;
    permitted_form_types: string[];
  }>;
  default_wcb_config: {
    wcb_config_id: string;
    contract_id: string;
    role_code: string;
  } | null;
  submission_preferences: {
    ahcip_submission_mode: string;
    wcb_submission_mode: string;
    batch_review_reminder: boolean;
    deadline_reminder_days: number;
  } | null;
  hlink_accreditation_status: string | null;
  hlink_submitter_prefix: string | null;
  onboarding_completed: boolean;
  status: string;
}
