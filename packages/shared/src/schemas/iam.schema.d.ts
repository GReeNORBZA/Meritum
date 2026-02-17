import { z } from 'zod';
export declare const registerSchema: z.ZodObject<{
    email: z.ZodString;
    password: z.ZodString;
    full_name: z.ZodString;
    phone: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    email: string;
    password: string;
    full_name: string;
    phone?: string | undefined;
}, {
    email: string;
    password: string;
    full_name: string;
    phone?: string | undefined;
}>;
export type Register = z.infer<typeof registerSchema>;
export declare const verifyEmailSchema: z.ZodObject<{
    token: z.ZodString;
}, "strip", z.ZodTypeAny, {
    token: string;
}, {
    token: string;
}>;
export type VerifyEmail = z.infer<typeof verifyEmailSchema>;
export declare const mfaConfirmSchema: z.ZodObject<{
    totp_code: z.ZodString;
}, "strip", z.ZodTypeAny, {
    totp_code: string;
}, {
    totp_code: string;
}>;
export type MfaConfirm = z.infer<typeof mfaConfirmSchema>;
export declare const loginSchema: z.ZodObject<{
    email: z.ZodString;
    password: z.ZodString;
}, "strip", z.ZodTypeAny, {
    email: string;
    password: string;
}, {
    email: string;
    password: string;
}>;
export type Login = z.infer<typeof loginSchema>;
export declare const loginMfaSchema: z.ZodObject<{
    mfa_session_token: z.ZodString;
    totp_code: z.ZodString;
}, "strip", z.ZodTypeAny, {
    totp_code: string;
    mfa_session_token: string;
}, {
    totp_code: string;
    mfa_session_token: string;
}>;
export type LoginMfa = z.infer<typeof loginMfaSchema>;
export declare const loginRecoverySchema: z.ZodObject<{
    mfa_session_token: z.ZodString;
    recovery_code: z.ZodString;
}, "strip", z.ZodTypeAny, {
    mfa_session_token: string;
    recovery_code: string;
}, {
    mfa_session_token: string;
    recovery_code: string;
}>;
export type LoginRecovery = z.infer<typeof loginRecoverySchema>;
export declare const passwordResetRequestSchema: z.ZodObject<{
    email: z.ZodString;
}, "strip", z.ZodTypeAny, {
    email: string;
}, {
    email: string;
}>;
export type PasswordResetRequest = z.infer<typeof passwordResetRequestSchema>;
export declare const passwordResetSchema: z.ZodObject<{
    token: z.ZodString;
    new_password: z.ZodString;
}, "strip", z.ZodTypeAny, {
    token: string;
    new_password: string;
}, {
    token: string;
    new_password: string;
}>;
export type PasswordReset = z.infer<typeof passwordResetSchema>;
export declare const sessionIdParamSchema: z.ZodObject<{
    id: z.ZodString;
}, "strip", z.ZodTypeAny, {
    id: string;
}, {
    id: string;
}>;
export type SessionIdParam = z.infer<typeof sessionIdParamSchema>;
export declare const delegateInviteSchema: z.ZodObject<{
    email: z.ZodString;
    permissions: z.ZodArray<z.ZodEnum<[string, ...string[]]>, "many">;
}, "strip", z.ZodTypeAny, {
    email: string;
    permissions: string[];
}, {
    email: string;
    permissions: string[];
}>;
export type DelegateInvite = z.infer<typeof delegateInviteSchema>;
export declare const delegateUpdatePermissionsSchema: z.ZodObject<{
    permissions: z.ZodArray<z.ZodEnum<[string, ...string[]]>, "many">;
}, "strip", z.ZodTypeAny, {
    permissions: string[];
}, {
    permissions: string[];
}>;
export type DelegateUpdatePermissions = z.infer<typeof delegateUpdatePermissionsSchema>;
export declare const delegateAcceptSchema: z.ZodObject<{
    token: z.ZodString;
    full_name: z.ZodOptional<z.ZodString>;
    password: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    token: string;
    password?: string | undefined;
    full_name?: string | undefined;
}, {
    token: string;
    password?: string | undefined;
    full_name?: string | undefined;
}>;
export type DelegateAccept = z.infer<typeof delegateAcceptSchema>;
export declare const delegateIdParamSchema: z.ZodObject<{
    id: z.ZodString;
}, "strip", z.ZodTypeAny, {
    id: string;
}, {
    id: string;
}>;
export type DelegateIdParam = z.infer<typeof delegateIdParamSchema>;
export declare const accountUpdateSchema: z.ZodObject<{
    full_name: z.ZodOptional<z.ZodString>;
    phone: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    full_name?: string | undefined;
    phone?: string | undefined;
}, {
    full_name?: string | undefined;
    phone?: string | undefined;
}>;
export type AccountUpdate = z.infer<typeof accountUpdateSchema>;
export declare const accountDeleteSchema: z.ZodObject<{
    password: z.ZodString;
    totp_code: z.ZodString;
    confirmation: z.ZodLiteral<"DELETE">;
}, "strip", z.ZodTypeAny, {
    password: string;
    totp_code: string;
    confirmation: "DELETE";
}, {
    password: string;
    totp_code: string;
    confirmation: "DELETE";
}>;
export type AccountDelete = z.infer<typeof accountDeleteSchema>;
export declare const mfaReconfigureSchema: z.ZodObject<{
    current_totp_code: z.ZodString;
}, "strip", z.ZodTypeAny, {
    current_totp_code: string;
}, {
    current_totp_code: string;
}>;
export type MfaReconfigure = z.infer<typeof mfaReconfigureSchema>;
export declare const auditLogQuerySchema: z.ZodObject<{
    action: z.ZodOptional<z.ZodString>;
    category: z.ZodOptional<z.ZodString>;
    start_date: z.ZodOptional<z.ZodString>;
    end_date: z.ZodOptional<z.ZodString>;
    page: z.ZodDefault<z.ZodNumber>;
    page_size: z.ZodDefault<z.ZodNumber>;
}, "strip", z.ZodTypeAny, {
    page: number;
    page_size: number;
    action?: string | undefined;
    category?: string | undefined;
    start_date?: string | undefined;
    end_date?: string | undefined;
}, {
    action?: string | undefined;
    category?: string | undefined;
    start_date?: string | undefined;
    end_date?: string | undefined;
    page?: number | undefined;
    page_size?: number | undefined;
}>;
export type AuditLogQuery = z.infer<typeof auditLogQuerySchema>;
//# sourceMappingURL=iam.schema.d.ts.map