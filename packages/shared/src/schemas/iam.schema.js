"use strict";
// ============================================================================
// Domain 1: Identity & Access Management — Zod Validation Schemas
// ============================================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.auditLogQuerySchema = exports.mfaReconfigureSchema = exports.accountDeleteSchema = exports.accountUpdateSchema = exports.delegateIdParamSchema = exports.delegateAcceptSchema = exports.delegateUpdatePermissionsSchema = exports.delegateInviteSchema = exports.sessionIdParamSchema = exports.passwordResetSchema = exports.passwordResetRequestSchema = exports.loginRecoverySchema = exports.loginMfaSchema = exports.loginSchema = exports.mfaConfirmSchema = exports.verifyEmailSchema = exports.registerSchema = void 0;
const zod_1 = require("zod");
const iam_constants_js_1 = require("../constants/iam.constants.js");
// --- Password validation (reusable) ---
// FRD §9: min 12 chars, must contain uppercase, lowercase, digit, special character
const passwordSchema = zod_1.z
    .string()
    .min(12, 'Password must be at least 12 characters')
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{12,}$/, 'Password must contain uppercase, lowercase, digit, and special character');
// --- TOTP code (reusable) ---
const totpCodeSchema = zod_1.z
    .string()
    .length(6, 'TOTP code must be exactly 6 digits')
    .regex(/^\d{6}$/, 'TOTP code must be exactly 6 digits');
// --- Registration ---
exports.registerSchema = zod_1.z.object({
    email: zod_1.z.string().email().max(255),
    password: passwordSchema,
    full_name: zod_1.z.string().min(1).max(200),
    phone: zod_1.z.string().max(20).optional(),
});
// --- Email Verification ---
exports.verifyEmailSchema = zod_1.z.object({
    token: zod_1.z.string().uuid(),
});
// --- MFA Setup Confirmation ---
exports.mfaConfirmSchema = zod_1.z.object({
    totp_code: totpCodeSchema,
});
// --- Login ---
exports.loginSchema = zod_1.z.object({
    email: zod_1.z.string().email().max(255),
    password: zod_1.z.string().min(1),
});
// --- Login MFA (step 2: TOTP) ---
exports.loginMfaSchema = zod_1.z.object({
    mfa_session_token: zod_1.z.string(),
    totp_code: totpCodeSchema,
});
// --- Login Recovery (step 2: recovery code) ---
exports.loginRecoverySchema = zod_1.z.object({
    mfa_session_token: zod_1.z.string(),
    recovery_code: zod_1.z.string(),
});
// --- Password Reset Request ---
exports.passwordResetRequestSchema = zod_1.z.object({
    email: zod_1.z.string().email().max(255),
});
// --- Password Reset (with token) ---
exports.passwordResetSchema = zod_1.z.object({
    token: zod_1.z.string().uuid(),
    new_password: passwordSchema,
});
// --- Session ID Parameter ---
exports.sessionIdParamSchema = zod_1.z.object({
    id: zod_1.z.string().uuid(),
});
// --- Permission keys enum for delegate schemas ---
const PERMISSION_KEYS = Object.values(iam_constants_js_1.Permission).filter((p) => p !== iam_constants_js_1.Permission.ADMIN_PHI_ACCESS);
const permissionEnum = zod_1.z.enum(PERMISSION_KEYS);
// --- Delegate Invite ---
exports.delegateInviteSchema = zod_1.z.object({
    email: zod_1.z.string().email().max(255),
    permissions: zod_1.z.array(permissionEnum).min(1),
});
// --- Delegate Update Permissions ---
exports.delegateUpdatePermissionsSchema = zod_1.z.object({
    permissions: zod_1.z.array(permissionEnum).min(1),
});
// --- Delegate Accept ---
exports.delegateAcceptSchema = zod_1.z.object({
    token: zod_1.z.string(),
    full_name: zod_1.z.string().min(1).max(200).optional(),
    password: passwordSchema.optional(),
});
// --- Delegate ID Parameter ---
exports.delegateIdParamSchema = zod_1.z.object({
    id: zod_1.z.string().uuid(),
});
// --- Account Update ---
exports.accountUpdateSchema = zod_1.z.object({
    full_name: zod_1.z.string().min(1).max(200).optional(),
    phone: zod_1.z.string().max(20).optional(),
});
// --- Account Delete ---
exports.accountDeleteSchema = zod_1.z.object({
    password: zod_1.z.string().min(1),
    totp_code: totpCodeSchema,
    confirmation: zod_1.z.literal('DELETE'),
});
// --- MFA Reconfigure ---
exports.mfaReconfigureSchema = zod_1.z.object({
    current_totp_code: totpCodeSchema,
});
// --- Audit Log Query ---
exports.auditLogQuerySchema = zod_1.z.object({
    action: zod_1.z.string().optional(),
    category: zod_1.z.string().optional(),
    start_date: zod_1.z.string().date().optional(),
    end_date: zod_1.z.string().date().optional(),
    page: zod_1.z.coerce.number().int().min(1).default(1),
    page_size: zod_1.z.coerce.number().int().min(1).max(200).default(50),
});
//# sourceMappingURL=iam.schema.js.map