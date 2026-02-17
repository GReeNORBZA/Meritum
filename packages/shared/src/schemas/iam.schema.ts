// ============================================================================
// Domain 1: Identity & Access Management — Zod Validation Schemas
// ============================================================================

import { z } from 'zod';
import { Permission } from '../constants/iam.constants.js';

// --- Password validation (reusable) ---
// FRD §9: min 12 chars, must contain uppercase, lowercase, digit, special character

const passwordSchema = z
  .string()
  .min(12, 'Password must be at least 12 characters')
  .regex(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{12,}$/,
    'Password must contain uppercase, lowercase, digit, and special character',
  );

// --- TOTP code (reusable) ---

const totpCodeSchema = z
  .string()
  .length(6, 'TOTP code must be exactly 6 digits')
  .regex(/^\d{6}$/, 'TOTP code must be exactly 6 digits');

// --- Registration ---

export const registerSchema = z.object({
  email: z.string().email().max(255),
  password: passwordSchema,
  full_name: z.string().min(1).max(200),
  phone: z.string().max(20).optional(),
});

export type Register = z.infer<typeof registerSchema>;

// --- Email Verification ---

export const verifyEmailSchema = z.object({
  token: z.string().uuid(),
});

export type VerifyEmail = z.infer<typeof verifyEmailSchema>;

// --- MFA Setup Confirmation ---

export const mfaConfirmSchema = z.object({
  totp_code: totpCodeSchema,
});

export type MfaConfirm = z.infer<typeof mfaConfirmSchema>;

// --- Login ---

export const loginSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(1),
});

export type Login = z.infer<typeof loginSchema>;

// --- Login MFA (step 2: TOTP) ---

export const loginMfaSchema = z.object({
  mfa_session_token: z.string(),
  totp_code: totpCodeSchema,
});

export type LoginMfa = z.infer<typeof loginMfaSchema>;

// --- Login Recovery (step 2: recovery code) ---

export const loginRecoverySchema = z.object({
  mfa_session_token: z.string(),
  recovery_code: z.string(),
});

export type LoginRecovery = z.infer<typeof loginRecoverySchema>;

// --- Password Reset Request ---

export const passwordResetRequestSchema = z.object({
  email: z.string().email().max(255),
});

export type PasswordResetRequest = z.infer<typeof passwordResetRequestSchema>;

// --- Password Reset (with token) ---

export const passwordResetSchema = z.object({
  token: z.string().uuid(),
  new_password: passwordSchema,
});

export type PasswordReset = z.infer<typeof passwordResetSchema>;

// --- Session ID Parameter ---

export const sessionIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type SessionIdParam = z.infer<typeof sessionIdParamSchema>;

// --- Permission keys enum for delegate schemas ---

const PERMISSION_KEYS = Object.values(Permission).filter(
  (p): p is Exclude<Permission, 'ADMIN_PHI_ACCESS'> => p !== Permission.ADMIN_PHI_ACCESS,
);

const permissionEnum = z.enum(
  PERMISSION_KEYS as [string, ...string[]],
);

// --- Delegate Invite ---

export const delegateInviteSchema = z.object({
  email: z.string().email().max(255),
  permissions: z.array(permissionEnum).min(1),
});

export type DelegateInvite = z.infer<typeof delegateInviteSchema>;

// --- Delegate Update Permissions ---

export const delegateUpdatePermissionsSchema = z.object({
  permissions: z.array(permissionEnum).min(1),
});

export type DelegateUpdatePermissions = z.infer<typeof delegateUpdatePermissionsSchema>;

// --- Delegate Accept ---

export const delegateAcceptSchema = z.object({
  token: z.string(),
  full_name: z.string().min(1).max(200).optional(),
  password: passwordSchema.optional(),
});

export type DelegateAccept = z.infer<typeof delegateAcceptSchema>;

// --- Delegate ID Parameter ---

export const delegateIdParamSchema = z.object({
  id: z.string().uuid(),
});

export type DelegateIdParam = z.infer<typeof delegateIdParamSchema>;

// --- Account Update ---

export const accountUpdateSchema = z.object({
  full_name: z.string().min(1).max(200).optional(),
  phone: z.string().max(20).optional(),
});

export type AccountUpdate = z.infer<typeof accountUpdateSchema>;

// --- Account Delete ---

export const accountDeleteSchema = z.object({
  password: z.string().min(1),
  totp_code: totpCodeSchema,
  confirmation: z.literal('DELETE'),
});

export type AccountDelete = z.infer<typeof accountDeleteSchema>;

// --- MFA Reconfigure ---

export const mfaReconfigureSchema = z.object({
  current_totp_code: totpCodeSchema,
});

export type MfaReconfigure = z.infer<typeof mfaReconfigureSchema>;

// --- Audit Log Query ---

export const auditLogQuerySchema = z.object({
  action: z.string().optional(),
  category: z.string().optional(),
  start_date: z.string().date().optional(),
  end_date: z.string().date().optional(),
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(200).default(50),
});

export type AuditLogQuery = z.infer<typeof auditLogQuerySchema>;
