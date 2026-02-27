# Meritum_Domain_01_Identity_Access_1

MERITUM

Functional Requirements

Identity & Access Domain

Domain 1 of 13  |  Critical Path: Position 1

Meritum Health Technologies Inc.

Version 2.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The Identity & Access domain is the security perimeter of Meritum. It governs who can access the platform, how they authenticate, what they are authorised to do, and how all access is recorded. Every other domain depends on Identity & Access for authentication context and authorisation decisions.

This domain handles Protected Health Information (PHI) indirectly—it does not store clinical data, but it controls who can access clinical data stored in other domains. A failure in this domain is a failure of the entire platform's security posture under the Health Information Act (HIA).

Updated: This domain also provides cross-cutting PHI read-access audit logging via middleware, IMA amendment gating, and breach notification infrastructure required under HIA §§60–62.

## 1.2 Scope

User registration (physician and admin accounts)

Authentication (email/password + mandatory TOTP MFA)

Session management (token lifecycle, expiry, revocation)

Role-based access control (RBAC): Physician, Delegate, Admin, Practice Admin

Delegate management (invitation, permission scoping, batch approval authority)

Audit logging (all authentication, authorisation, and PHI access events)

Account lifecycle (password reset, MFA recovery, account suspension, account deletion)

Subscription status integration (Stripe webhook-driven access control)

Secondary email management (dual-delivery for critical compliance notifications)

IMA amendment acknowledgement gating (blocking middleware until physician responds)

Breach notification infrastructure (admin-only breach record management, 72-hour OIPC compliance)

PHI read-access audit logging (cross-cutting middleware on GET routes returning PHI)

## 1.3 Out of Scope

Stripe payment processing (Platform Operations domain)

Physician profile data beyond auth (Provider Management domain)

Patient data access decisions at the record level (Claim Lifecycle domain)

Notification delivery (Notification Service domain; Identity & Access emits events)

Practice/clinic tier management — entity creation, seat management, consolidated billing (Platform Operations domain; PRACTICE_ADMIN role definition lives here in Domain 1)

## 1.4 Domain Dependencies

# 2. Roles & Permissions Model

## 2.1 Role Definitions

Updated: Four roles are implemented. The original three (Physician, Delegate, Admin) are augmented with Practice Admin for clinic/practice tier management.

| Role | Description | Created By |
| --- | --- | --- |
| Physician (`PHYSICIAN`) | Primary account holder. Full access to all data and features under their BA number(s). Can manage delegates, configure submission preferences, approve batches, export data, manage subscription. Data custodian under HIA. | Self-registration |
| Delegate (`DELEGATE`) | Granted access by a Physician. Scoped to one or more Physician accounts. Permissions are configurable per Physician. Cannot create their own account independently—must be invited by a Physician. | Physician invitation |
| Admin (`ADMIN`) | Platform administrator. System-wide access for support, configuration, and monitoring. Cannot access PHI unless explicitly granted by a Physician for support purposes (logged and time-limited). Manages IMA amendments and breach notifications. | System provisioned |
| Practice Admin (`PRACTICE_ADMIN`) | Clinic/practice administrator. Scoped to seat management, invoice viewing, and practice settings editing. Explicitly excluded from all claim, patient, and analytics access. A Practice Admin may also hold a separate Physician account. | Assigned when creating a practice entity (Platform Operations domain) |

Design note: The Physician role is the data custodian under HIA. No other role can perform actions that the Physician has not explicitly authorised. The Delegate role exists to reduce administrative burden, not to operate independently. The Admin role is for platform operations and must not access PHI without Physician consent and audit trail. The Practice Admin role is strictly limited to practice account management—exposing individual physician billing data to a practice administrator would create a surveillance dynamic (per pricing strategy §2.4).

## 2.2 Permission Matrix

Updated: 29 permission keys are implemented. The original set is extended with AI Coach, practice management, and admin PHI access permissions.

| Permission Key | Physician | Delegate (Configurable) | Admin | Practice Admin |
| --- | --- | --- | --- | --- |
| `CLAIM_CREATE` | Always | Configurable | Never | Never |
| `CLAIM_VIEW` | Always | Configurable | Support access only (logged, time-limited) | Never |
| `CLAIM_EDIT` | Always | Configurable | Never | Never |
| `CLAIM_DELETE` | Always | Configurable | Never | Never |
| `CLAIM_SUBMIT` | Always | Configurable | Never | Never |
| `BATCH_VIEW` | Always | Configurable | Never | Never |
| `BATCH_APPROVE` | Always | Configurable (batch approval authority) | Never | Never |
| `PATIENT_CREATE` | Always | Configurable | Never | Never |
| `PATIENT_VIEW` | Always | Configurable | Never | Never |
| `PATIENT_EDIT` | Always | Configurable | Never | Never |
| `PATIENT_IMPORT` | Always | Configurable | Never | Never |
| `REPORT_VIEW` | Always | Configurable | Never | Never |
| `REPORT_EXPORT` | Always | Configurable | Never | Never |
| `ANALYTICS_VIEW` | Always | Configurable | System-level only | Never |
| `PROVIDER_VIEW` | Always | Configurable | Never | Never |
| `PROVIDER_EDIT` | Always | Configurable | Never | Never |
| `DELEGATE_MANAGE` | Always | Never (forbidden) | Never | Never |
| `SUBSCRIPTION_MANAGE` | Always | Never (forbidden) | Never | Never |
| `SETTINGS_VIEW` | Always | Configurable | Never | Never |
| `SETTINGS_EDIT` | Always | Configurable | Never | Never |
| `DATA_EXPORT` | Always | Never (forbidden) | Never | Never |
| `AUDIT_VIEW` | Always | Never | System-wide | Never |
| `AI_COACH_VIEW` | Always | Configurable | Never | Never |
| `AI_COACH_MANAGE` | Always | Configurable | Never | Never |
| `PRACTICE_SEAT_VIEW` | Never | Never | Never | Always |
| `PRACTICE_SEAT_MANAGE` | Never | Never | Never | Always |
| `PRACTICE_INVOICE_VIEW` | Never | Never | Never | Always |
| `PRACTICE_SETTINGS_EDIT` | Never | Never | Never | Always |
| `ADMIN_PHI_ACCESS` | Never | Never | Always (logged, time-limited) | Never |

Delegate permissions are configurable per Physician-Delegate relationship. A Delegate may serve multiple Physicians with different permission sets for each.

The following permissions cannot be granted to delegates: `DELEGATE_MANAGE`, `SUBSCRIPTION_MANAGE`, `DATA_EXPORT`. This is enforced at the service layer during invitation and permission update operations.

# 3. User Stories & Acceptance Criteria

## 3.1 Registration & Onboarding

| IAM-001 | Physician Registration |
| --- | --- |
| User Story | As a physician, I want to create a Meritum account so that I can begin setting up my billing profile. |
| Acceptance Criteria | • Registration form collects: full name, email address, password, and optionally a phone number (for MFA recovery). • Email address must be unique across the platform. • Anti-enumeration: if email already exists, the system returns an identical success response and emits a `USER_ALREADY_EXISTS` event so the notification service can warn the existing account holder. A dummy Argon2id hash is performed to keep response timing consistent. • Password must meet minimum requirements: ≥12 characters, ≥1 uppercase, ≥1 lowercase, ≥1 digit, ≥1 special character. Password strength indicator displayed in real-time. • Password is hashed using Argon2id (memory=19,456 KiB, iterations=2, parallelism=1) via `@node-rs/argon2`. Plaintext password is never stored or logged. • On successful registration, a verification token (UUID, SHA-256 hashed before storage) is generated with 24-hour expiry. A `USER_REGISTERED` event is emitted for the notification service to send a verification email. • Account is created in "trial" subscription status. Access to billing features is gated until email verification and MFA setup are complete. • Registration event is logged in the audit trail (action: `auth.registered`). |

| IAM-002 | Mandatory MFA Setup |
| --- | --- |
| User Story | As a newly registered physician, I want to set up two-factor authentication so that my account is protected against credential compromise. |
| Acceptance Criteria | • After email verification, the user is presented with a TOTP setup screen showing a QR code and a manual entry key. • The TOTP secret is generated server-side using `otplib.authenticator.generateSecret()`. Secret is encrypted at rest using AES-256-GCM before storage. The encryption key is sourced from the `TOTP_ENCRYPTION_KEY` environment variable (hex-encoded). • QR code encodes the otpauth:// URI with issuer="Meritum", account=user's email, algorithm=SHA1, digits=6, period=30s. • User must enter a valid TOTP code from their authenticator app to confirm setup. The system verifies the code before activating MFA. • Upon successful MFA setup, the system generates 10 single-use recovery codes (8 alphanumeric characters each, formatted as XXXX-XXXX for readability). Character set excludes ambiguous characters (no 0/O, 1/I). These are displayed once and must be acknowledged by the user. • Recovery codes are hashed with Argon2id (same parameters as passwords). They cannot be retrieved—only regenerated (which invalidates all previous codes). • MFA setup event is logged: action `auth.mfa_setup`. • `MFA_SETUP_COMPLETE` event emitted for downstream consumers. |

## 3.2 Authentication

| IAM-003 | Delegate Invitation |
| --- | --- |
| User Story | As a physician, I want to invite a delegate (e.g., my office administrator) to access my billing on my behalf so that I can share the workload without sharing my credentials. |
| Acceptance Criteria | • Physician enters the delegate's email address and selects permissions from the configurable permission set (see Section 2.2). • Permissions are validated against the allowed delegate permission set. Forbidden permissions (`DELEGATE_MANAGE`, `SUBSCRIPTION_MANAGE`, `DATA_EXPORT`) are rejected with a 422 error. • System generates a single-use invitation token (UUID, SHA-256 hashed before storage) with 72-hour expiry. A `DELEGATE_INVITED` event is emitted for the notification service. • If the delegate already has a Meritum account (as a delegate for another physician), they can accept the invitation and add this physician to their existing account. No new registration required. • If the delegate does not have an account, clicking the invitation link opens a registration form (name, email pre-filled, password). MFA setup is mandatory for delegates as well. • On acceptance, the Delegate's account is linked to the Physician's account with the configured permissions. The delegate user is created with role `DELEGATE`. • A Delegate can be linked to multiple Physicians. Each linkage has its own independent permission set. One linkage per physician-delegate pair (enforced by unique index). • Physician can view all active delegates, their permission sets, and their last login time. • Invitation event logged: action `delegate.invited`. Acceptance event logged: action `delegate.accepted`. |

| IAM-004 | Login |
| --- | --- |
| User Story | As a registered user, I want to log in to Meritum so that I can access my billing features. |
| Acceptance Criteria | • Login is a two-step process. Step 1: email/password verification. Step 2: TOTP or recovery code verification. • Step 1: User enters email and password. The system normalises the email to lowercase and looks up the user. Anti-enumeration: if the email does not exist, a dummy Argon2id hash is performed to keep response timing consistent. Returns a generic "Invalid credentials" error for both wrong email and wrong password. • Account lockout: if `lockedUntil` is in the future, the login attempt is rejected with an "Account is temporarily locked" error. • Password verification uses `@node-rs/argon2.verify()`. On failure, `failedLoginCount` is atomically incremented. At 10 failed attempts, the account is locked for 30 minutes. • On successful password verification, an HMAC-signed MFA session token is generated (5-minute expiry) containing the userId. This token is returned to the client for Step 2. • Step 2 (TOTP): The MFA session token is verified using constant-time comparison (`timingSafeEqual`). The TOTP code is verified against the decrypted secret using `otplib.authenticator.verify()`. On success, `failedLoginCount` is reset to 0. • A session is created: 32 random bytes (hex-encoded) as the session token. The SHA-256 hash of the token is stored in the sessions table. The plaintext token is set as an HTTP-only cookie. • Audit events: `auth.login_success` (password step), `auth.login_mfa_success` (TOTP step), `auth.login_failed` (password failure), `auth.login_mfa_failed` (TOTP failure). • If the account is in "suspended" state (e.g., payment failure), login succeeds but access is restricted to account management and data export only. |

| IAM-005 | MFA Recovery |
| --- | --- |
| User Story | As a user who has lost access to my authenticator app, I want to use a recovery code to log in so that I am not permanently locked out. |
| Acceptance Criteria | • After entering valid email/password (Step 1), the user provides a recovery code instead of a TOTP code (Step 2 alternative). • The recovery code is normalised (dashes stripped, uppercased) and verified against all unused recovery code hashes for the user using Argon2id. This is intentionally slow for security. • If a match is found, the matched code is marked as used (single-use). `failedLoginCount` is reset. A session is created identically to TOTP login. The remaining code count is returned to the client. • If no match, `failedLoginCount` is incremented. An `auth.login_mfa_failed` audit event is logged with method `recovery_code`. • After successful recovery login, the user is prompted (but not forced) to reconfigure TOTP with a new secret. • Audit event logged: action `auth.login_recovery_used` with remaining code count. |

| IAM-006 | Session Management |
| --- | --- |
| User Story | As a logged-in user, I want my session to be secure and expire after a reasonable period of inactivity so that my account is protected if I forget to log out. |
| Acceptance Criteria | • On successful authentication, the server issues an opaque session token (32 random bytes, hex-encoded). The SHA-256 hash is stored in the `sessions` table. • Session token has two expiry parameters: absolute expiry (24 hours from creation) and idle expiry (60 minutes since last activity). Whichever is reached first invalidates the session. Expiry is checked at the application layer in `isSessionExpired()`. • Session token is transmitted via HTTP-only, Secure, SameSite=Lax cookie with Path=/ and Max-Age=86400. • Each API request validates the session token hash, checks expiry, and refreshes the idle timer (`lastActiveAt`). • User can explicitly log out, which revokes the session with reason `logout` and clears the session cookie. • User can view active sessions (sessionId, ip, user_agent, created_at, last_active_at) and revoke any session remotely (reason: `revoked_remote`). "Log out everywhere" revokes all sessions except current. • Session creation and destruction events logged with appropriate audit actions. • Concurrent sessions are allowed. Each session is independently tracked and revocable. • Expired revoked sessions are cleaned up by a background job after 30 days. |

| IAM-007 | Password Reset |
| --- | --- |
| User Story | As a user who has forgotten my password, I want to reset it securely so that I can regain access to my account. |
| Acceptance Criteria | • User enters their email on the password reset form. • System always responds with "If an account exists, a password reset email has been sent" (anti-enumeration). A dummy Argon2id hash is performed when the email does not exist. • If the account exists, a password reset token (UUID, SHA-256 hashed before storage) is generated with 1-hour expiry. A `USER_PASSWORD_RESET_REQUESTED` event is emitted. • Clicking the link opens a form to set a new password. Same password requirements as registration (IAM-001). • On successful reset: token is marked as consumed, new password is hashed with Argon2id, all existing sessions are invalidated with reason `password_reset`. • The user must re-authenticate with the new password + TOTP. • Audit events: `auth.password_reset_requested`, `auth.password_reset_completed`. |

## 3.3 Delegate Management

| IAM-008 | Delegate Permission Modification |
| --- | --- |
| User Story | As a physician, I want to modify my delegate's permissions so that I can adjust their access as our working relationship evolves. |
| Acceptance Criteria | • Physician navigates to delegate management and selects a delegate by linkage ID. • Permissions are validated against the allowed delegate set. Forbidden permissions are rejected. • Changes take effect immediately on next API request from the delegate. No active session invalidation required (permissions checked on each request from the delegate linkage, not baked into token). • Audit event: `delegate.permissions_updated` with new permission set and `canApproveBatches` flag. |

| IAM-009 | Delegate Removal |
| --- | --- |
| User Story | As a physician, I want to remove a delegate's access to my account so that they can no longer view or manage my billing. |
| Acceptance Criteria | • Physician selects a delegate linkage and confirms removal. • On confirmation: the linkage is deactivated (soft delete, `isActive = false`). All active sessions for this delegate user are immediately revoked with reason `revoked_remote`. • If the Delegate serves other Physicians, their access to those accounts is unaffected. • Audit event: `delegate.revoked`. A `DELEGATE_REVOKED` event is emitted for notification service. |

| IAM-010 | Batch Approval Authority |
| --- | --- |
| User Story | As a physician, I want to grant my delegate the authority to approve claim batches on my behalf so that submissions are not delayed when I'm unavailable. |
| Acceptance Criteria | • Batch approval authority is tracked via the `canApproveBatches` boolean on the delegate linkage. • When granted, the delegate can access the pre-submission review screen and approve or hold flagged claims for the physician's account. • The delegate's approval is functionally equivalent to the physician's for submission purposes. • All delegate batch approvals are logged in the audit trail. • Batch approval authority can be granted and revoked at any time via delegate permission management (IAM-008). |

| IAM-010b | Delegate Context Switching |
| --- | --- |
| User Story | As a delegate serving multiple physicians, I want to switch between physician contexts so that I can work on different physicians' data. |
| Acceptance Criteria | • Delegate calls `switchPhysicianContext()` with the target physician's user ID. • The system verifies an active linkage exists between the delegate and the target physician. If no active linkage, returns an error. • The delegate's auth context is populated with the physician's user ID and the delegate's permission set for that physician. • All downstream domain queries are scoped to the active physician's data. • Audit event: `delegate.context_switched`. |

## 3.4 Account Lifecycle

| IAM-011 | Account Suspension (Payment Failure) |
| --- | --- |
| User Story | As the system, I want to suspend accounts with failed payments so that access is gated behind active subscription, while ensuring physicians can still access their data. |
| Acceptance Criteria | • Subscription status is checked via `checkSubscriptionAccess()` which derives an access level: `TRIAL` or `ACTIVE` → `full` access; `PAST_DUE` → `read_only` (can view but not create/submit); `SUSPENDED` or `CANCELLED` → `suspended` (no access except account management). • A prominent banner is displayed on all screens explaining the suspension. • If payment is resolved, account immediately transitions back to "active". No data loss, no re-onboarding. • Suspension and reactivation events logged: `account.suspended`, `account.reactivated`. |

| IAM-012 | Account Deletion |
| --- | --- |
| User Story | As a physician, I want to delete my account so that my data is removed from the platform when I no longer need it. |
| Acceptance Criteria | • Account deletion requires three-factor confirmation: (1) correct password (Argon2id verified), (2) valid TOTP code, (3) typed confirmation string exactly equals "DELETE". • On confirmation: `SUBSCRIPTION_CANCEL_REQUESTED` event emitted for Stripe cancellation; all active sessions invalidated with reason `account_deleted`; all delegate linkages deactivated (each delegate notified via `DELEGATE_ACCESS_REVOKED_ACCOUNT_DELETION` event); user account soft-deleted (`isActive = false`). • PHI data is scheduled for permanent deletion after a 30-day grace period (45 days per IMA requirements — see IMA amendment system). During the grace period, the physician can contact support to reverse the deletion. • Audit event: `account.deletion_requested` with scheduled deletion date and count of delegates deactivated. |

| IAM-013 | Subscription-Gated Access |
| --- | --- |
| User Story | As the system, I want to gate feature access based on subscription status so that only paying users can submit claims. |
| Acceptance Criteria | • Subscription status stored on the user record: `TRIAL`, `ACTIVE`, `PAST_DUE`, `SUSPENDED`, `CANCELLED`. • Access tiers based on subscription status: "TRIAL" and "ACTIVE" = full access; "PAST_DUE" = read-only; "SUSPENDED" and "CANCELLED" = suspended (account management + data export only). • Subscription status updated via Stripe webhook events processed by the Platform Operations domain. • Subscription status change events logged: `account.suspended`, `account.reactivated`. |

## 3.5 Secondary Email

| IAM-014 | Secondary Email Management |
| --- | --- |
| User Story | As a physician, I want to register a secondary email address so that I receive critical compliance notifications (IMA amendments, breach notifications) at both my primary and secondary email addresses. |
| Acceptance Criteria | • Physician can set or clear a secondary email via `PUT /api/v1/account/secondary-email`. • The secondary email must differ from the primary email. Format validated by Zod schema. • The secondary email is NOT an alternative login credential. It is used exclusively for dual-delivery of IMA amendment notifications and breach notifications. • Audit event: `account.secondary_email_updated` with old and new email values. |

Design note: Under HIA §§60–62, custodians must be notified of IMA changes and breaches promptly. A secondary email increases the likelihood of timely notification delivery, reducing regulatory risk.

# 4. Data Model

All timestamps are stored in UTC with timezone (`TIMESTAMPTZ`). All IDs are UUIDs (v4, generated by `defaultRandom()`). Sensitive fields (password, TOTP secret, recovery codes) are hashed or encrypted before storage and never returned in API responses.

## 4.1 Users Table

Updated: Includes `secondary_email` column for dual-delivery compliance notifications.

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| user_id | UUID | PK, defaultRandom() | Primary identifier |
| email | VARCHAR(255) | UNIQUE INDEX, NOT NULL | Login identifier; lowercase normalised |
| secondary_email | VARCHAR(100) | NULLABLE | Dual-delivery for IMA/breach notifications; not a login |
| password_hash | VARCHAR(255) | NOT NULL | Argon2id (memory=19456, iterations=2, parallelism=1) |
| full_name | VARCHAR(200) | NOT NULL | Display name |
| phone | VARCHAR(20) | NULLABLE | For MFA recovery; E.164 format |
| role | VARCHAR(20) | NOT NULL, DEFAULT 'physician' | `PHYSICIAN`, `DELEGATE`, `ADMIN`, `PRACTICE_ADMIN` |
| email_verified | BOOLEAN | NOT NULL, DEFAULT false | Set true on email verification |
| mfa_configured | BOOLEAN | NOT NULL, DEFAULT false | True after successful MFA setup |
| totp_secret_encrypted | TEXT | NULLABLE | TOTP secret; AES-256-GCM encrypted. Format: `iv:authTag:ciphertext` (all hex) |
| subscription_status | VARCHAR(20) | NOT NULL, DEFAULT 'trial' | `TRIAL`, `ACTIVE`, `PAST_DUE`, `SUSPENDED`, `CANCELLED` |
| failed_login_count | INTEGER | NOT NULL, DEFAULT 0 | Reset on successful login |
| locked_until | TIMESTAMPTZ | NULLABLE | Account lock expiry. Set when `failed_login_count` reaches 10 (30-minute lock). |
| is_active | BOOLEAN | NOT NULL, DEFAULT true | Soft delete for account deactivation |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT now() | Registration timestamp |
| updated_at | TIMESTAMPTZ | NOT NULL, DEFAULT now() | Last modification |

Indexes: `users_email_idx` (unique on email), `users_role_is_active_idx` (role + is_active), `users_subscription_status_idx` (subscription_status).

Protected fields: `email`, `passwordHash`, and `totpSecretEncrypted` cannot be modified through the generic `updateUser` method — they require dedicated functions (`setPasswordHash`, `setMfaSecret`, `updateSecondaryEmail`).

## 4.2 Recovery Codes Table

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| code_id | UUID | PK, defaultRandom() | |
| user_id | UUID | FK → users.user_id, NOT NULL | |
| code_hash | VARCHAR(255) | NOT NULL | Argon2id hash of recovery code (dash-stripped, uppercased) |
| used | BOOLEAN | NOT NULL, DEFAULT false | Set true on use; cannot be reused |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT now() | Regeneration deletes all existing unused codes first |

Index: `recovery_codes_user_id_used_idx` (user_id + used).

## 4.3 Sessions Table

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| session_id | UUID | PK, defaultRandom() | Session identifier |
| user_id | UUID | FK → users.user_id, NOT NULL | |
| token_hash | VARCHAR(255) | UNIQUE INDEX, NOT NULL | SHA-256 hash of session token (plaintext only in cookie) |
| ip_address | VARCHAR(45) | NOT NULL | Client IP at session creation |
| user_agent | TEXT | NOT NULL | Browser/device identification |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT now() | Absolute expiry = created_at + 24h |
| last_active_at | TIMESTAMPTZ | NOT NULL, DEFAULT now() | Idle expiry = last_active_at + 60min |
| revoked | BOOLEAN | NOT NULL, DEFAULT false | Set true on logout or revocation |
| revoked_reason | VARCHAR(30) | NULLABLE | `logout`, `expired_idle`, `expired_absolute`, `revoked_remote`, `password_reset`, `account_deleted` |

Indexes: `sessions_token_hash_idx` (unique on token_hash), `sessions_user_id_revoked_idx` (user_id + revoked), `sessions_last_active_at_idx` (last_active_at).

## 4.4 Delegate Linkages Table

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| linkage_id | UUID | PK, defaultRandom() | |
| physician_user_id | UUID | FK → users.user_id, NOT NULL | The physician granting access |
| delegate_user_id | UUID | FK → users.user_id, NOT NULL | The delegate receiving access |
| permissions | JSONB | NOT NULL, typed as string[] | Permission set as array of permission keys |
| can_approve_batches | BOOLEAN | NOT NULL, DEFAULT false | Batch approval authority flag |
| is_active | BOOLEAN | NOT NULL, DEFAULT true | Set false on removal (soft delete for audit) |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT now() | |
| updated_at | TIMESTAMPTZ | NOT NULL, DEFAULT now() | |

Indexes: `delegate_linkages_physician_delegate_idx` (unique on physician_user_id + delegate_user_id), `delegate_linkages_delegate_is_active_idx` (delegate_user_id + is_active).

## 4.5 Invitation Tokens Table

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| invitation_id | UUID | PK, defaultRandom() | |
| physician_user_id | UUID | FK → users.user_id, NOT NULL | Who sent the invitation |
| delegate_email | VARCHAR(255) | NOT NULL | Invitee email (lowercase) |
| token_hash | VARCHAR(255) | UNIQUE INDEX, NOT NULL | SHA-256 hash of invitation token |
| permissions | JSONB | NOT NULL | Intended permissions on acceptance |
| expires_at | TIMESTAMPTZ | NOT NULL | 72 hours from creation |
| accepted | BOOLEAN | NOT NULL, DEFAULT false | |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT now() | |

Indexes: `invitation_tokens_token_hash_idx` (unique on token_hash), `invitation_tokens_physician_accepted_idx` (physician_user_id + accepted).

## 4.6 Audit Log Table

Retention: Audit logs are retained for 7 years per HIA record-keeping requirements. Logs are append-only—no row may be updated or deleted. The audit log table should be partitioned by month for query performance.

Updated: The audit log now records PHI read-access events (GET routes) in addition to state changes and authentication events.

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| log_id | UUID | PK, defaultRandom() | Append-only; no UPDATE or DELETE permitted |
| user_id | UUID | NULLABLE (FK → users.user_id) | NULL for anonymous events (failed login with unknown email) |
| action | VARCHAR(50) | NOT NULL | Structured action identifier (see Section 6) |
| category | VARCHAR(20) | NOT NULL | `auth`, `delegate`, `account`, `audit`, `admin` |
| resource_type | VARCHAR(50) | NULLABLE | user, session, delegate_linkage, invitation, etc. |
| resource_id | UUID | NULLABLE | ID of affected resource |
| detail | JSONB | NULLABLE | Additional context. Sensitive keys are redacted before storage. |
| ip_address | VARCHAR(45) | NULLABLE | Client IP |
| user_agent | TEXT | NULLABLE | Browser/device |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT now() | Event occurrence time (UTC) |

Indexes: `audit_log_user_id_created_at_idx` (user_id + created_at), `audit_log_action_created_at_idx` (action + created_at), `audit_log_resource_type_resource_id_created_at_idx` (resource_type + resource_id + created_at).

Sensitive detail key sanitisation: The repository layer redacts the following keys before writing to JSONB: `password`, `passwordHash`, `password_hash`, `newPassword`, `new_password`, `currentPassword`, `current_password`, `token`, `tokenHash`, `token_hash`, `totpSecret`, `totp_secret`, `totpSecretEncrypted`, `totp_secret_encrypted`, `sessionToken`, `session_token`, `mfa_session_token`, `recovery_code`, `codeHash`, `code_hash`. Redacted values are replaced with `[REDACTED]`.

## 4.7 IMA Amendment Tables (Platform Operations Domain, Referenced Here)

The IMA amendment and breach notification tables are defined in the Platform Operations domain schema (`packages/shared/src/schemas/db/platform.schema.ts`) but have cross-cutting interaction with Domain 1:

- **`ima_amendments`**: Amendment records (type, title, description, document text, effective date, status). Admin-created.
- **`ima_amendment_responses`**: Per-physician responses (acknowledged/accepted/rejected). Amendment gating middleware blocks platform access until the physician has responded to all pending amendments.
- **`breach_records`**: Breach records with 72-hour OIPC notification tracking. Admin-only.
- **`breach_affected_custodians`**: Maps breach records to affected physicians.
- **`breach_updates`**: Timeline entries for each breach record.
- **`data_destruction_tracking`**: Tracks data destruction lifecycle for account deletion and breach evidence holds.

Design note: These tables are defined in the Platform Operations domain because they are managed by admin-only routes in that domain. However, the IMA amendment gating middleware is a Domain 1 cross-cutting concern—it intercepts requests at the auth middleware layer and blocks access until pending amendments are acknowledged.

# 5. API Contracts

All endpoints use JSON request/response bodies. All responses include appropriate HTTP status codes. All endpoints (except registration, login, and password reset) require a valid session token. All requests are logged in the audit trail.

## 5.1 Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
| --- | --- | --- | --- |
| POST | /api/v1/auth/register | Create new physician account. Body: `{ email, password, full_name, phone? }`. Returns: `{ data: { userId } }`. Rate-limited (auth). | No |
| POST | /api/v1/auth/verify-email | Verify email with token. Body: `{ token }` (UUID). Returns: `{ data: { mfa_setup_required: true } }`. Rate-limited (auth). | No |
| POST | /api/v1/auth/mfa/setup | Initiate MFA setup. Returns: `{ data: { qr_code_uri, manual_key } }`. | Yes (email-verified) |
| POST | /api/v1/auth/mfa/confirm | Confirm MFA with first TOTP code. Body: `{ totp_code }` (6 digits). Returns: `{ data: { recovery_codes: [...] } }`. | Yes (partial) |
| POST | /api/v1/auth/login | Step 1: email/password. Body: `{ email, password }`. Returns: `{ data: { mfa_required: true, mfa_session_token } }`. Rate-limited (auth). | No |
| POST | /api/v1/auth/login/mfa | Step 2: TOTP code. Body: `{ mfa_session_token, totp_code }`. Returns: `{ data: { message } }`. Sets session cookie. Rate-limited (auth). | No |
| POST | /api/v1/auth/login/recovery | Step 2 alt: recovery code. Body: `{ mfa_session_token, recovery_code }`. Returns: `{ data: { message, remaining_codes } }`. Sets session cookie. Rate-limited (auth). | No |
| POST | /api/v1/auth/logout | Invalidate current session. Clears session cookie. | Yes |
| POST | /api/v1/auth/password/reset-request | Request password reset. Body: `{ email }`. Always returns 200 with success message. Rate-limited (auth). | No |
| POST | /api/v1/auth/password/reset | Reset password with token. Body: `{ token, new_password }`. Invalidates all sessions. Rate-limited (auth). | No |

## 5.2 Session Endpoints

| Method | Endpoint | Description | Auth Required |
| --- | --- | --- | --- |
| GET | /api/v1/sessions | List active sessions for current user. Returns: `{ data: [{ sessionId, ipAddress, userAgent, createdAt, lastActiveAt }] }`. | Yes |
| DELETE | /api/v1/sessions/:id | Revoke a specific session. Params validated as UUID. Returns 204. | Yes |
| DELETE | /api/v1/sessions | Revoke all sessions except current ("Log out everywhere"). Returns: `{ data: { message } }`. | Yes |

## 5.3 Delegate Management Endpoints

| Method | Endpoint | Description | Auth Required |
| --- | --- | --- | --- |
| POST | /api/v1/delegates/invite | Invite a delegate. Body: `{ email, permissions }`. Returns: `{ data: { invitationId, token } }`. | Yes (Physician or Admin) |
| GET | /api/v1/delegates | List all delegates for the current physician. Returns: `{ data: [{ linkageId, delegateUserId, fullName, email, permissions, canApproveBatches, lastLogin, isActive }] }`. | Yes (Physician or Admin) |
| PATCH | /api/v1/delegates/:id/permissions | Update delegate permissions. Body: `{ permissions }`. Params: `:id` = linkage UUID. Returns: `{ data: { linkageId } }`. | Yes (Physician or Admin) |
| DELETE | /api/v1/delegates/:id | Remove delegate access. Params: `:id` = linkage UUID. Invalidates delegate's sessions. Returns 204. | Yes (Physician or Admin) |
| POST | /api/v1/delegates/accept | Accept invitation. Body: `{ token, full_name?, password? }` (registration fields required for new users). Returns: `{ data: { linkageId } }`. Rate-limited (auth). | No (creates or links account) |
| GET | /api/v1/delegates/physicians | List physicians the current delegate serves. Returns: `{ data: [{ linkageId, physicianUserId, fullName, email, permissions, canApproveBatches }] }`. | Yes (Delegate) |

## 5.4 Account Management Endpoints

| Method | Endpoint | Description | Auth Required |
| --- | --- | --- | --- |
| GET | /api/v1/account | Get current user account info: userId, email, fullName, phone, role, subscriptionStatus, mfaConfigured, secondaryEmail. Audit-logged. | Yes |
| PATCH | /api/v1/account | Update account fields (full_name, phone). Email change requires re-verification (not supported here). | Yes |
| POST | /api/v1/account/mfa/regenerate-codes | Regenerate recovery codes. Requires current TOTP confirmation. Body: `{ totp_code }`. Invalidates all previous codes. Returns: `{ data: { recovery_codes } }`. | Yes |
| POST | /api/v1/account/mfa/reconfigure | Reconfigure TOTP (new secret). Requires current TOTP code. Body: `{ current_totp_code }`. Returns: `{ data: { qr_code_uri, manual_key } }`. User must call mfa/confirm again. | Yes |
| POST | /api/v1/account/delete | Request account deletion. Body: `{ password, totp_code, confirmation: "DELETE" }`. Returns: `{ data: { scheduledDeletionDate } }`. | Yes (Physician or Admin) |
| GET | /api/v1/account/audit-log | Paginated audit log for current user. Query: `{ action?, category?, start_date?, end_date?, page?, page_size? }`. Returns: `{ data: [...], pagination: { total, page, pageSize, hasMore } }`. Querying the audit log is itself logged (`audit.queried`). | Yes (Physician or Admin) |
| PUT | /api/v1/account/secondary-email | Set or clear secondary email. Body: `{ secondary_email }` (email string or null). Returns: `{ data: { secondary_email } }`. | Yes |

## 5.5 Auth Middleware (Internal)

Every API endpoint (except those marked "No" auth) passes through authentication and authorisation middleware:

**authenticate()**: Validates session token from HTTP-only cookie. Hashes the token with SHA-256 and looks up the session. Checks both absolute expiry (24h) and idle expiry (60min). Refreshes idle timer on success. Returns 401 Unauthorized if invalid/expired. Populates `request.authContext` with `AuthContext`.

**requireRole(...roles)**: Route-level preHandler that checks `authContext.role` against the required roles (case-insensitive comparison). Returns 403 Forbidden if the user's role is not in the allowed set.

**checkSubscription()**: Checks subscription status and derives access level (`full`, `read_only`, `suspended`). Returns 402 Payment Required if account is suspended. Allows read-only access for `PAST_DUE` accounts.

**auditLog(action, detail)**: Middleware-level audit logging. Routes with `config: { auditLog: true }` automatically append an audit log entry. Used for PHI read-access logging on GET routes.

**IMA Amendment Gate** (cross-cutting, defined in Platform Operations): Checks if the authenticated physician has any pending IMA amendments requiring response. If pending amendments exist and the request is not to the amendment response endpoint, returns 403 with `IMA_AMENDMENT_PENDING` error code. This forces physicians to acknowledge IMA amendments before accessing any platform features.

# 6. Audit Log Specification

The audit log is the compliance backbone of Meritum under HIA. Every access event, state change, and administrative action is recorded. The audit log is append-only, immutable, and retained for 7 years.

## 6.1 Action Identifiers

Updated: 28 action identifiers are implemented across 5 categories.

**Authentication Events (13 actions):**

| Action | Category | Logged Detail |
| --- | --- | --- |
| `auth.registered` | auth | email, IP |
| `auth.email_verified` | auth | user_id, IP |
| `auth.mfa_setup` | auth | user_id, method (TOTP), IP |
| `auth.login_success` | auth | user_id, step (password_verified), IP |
| `auth.login_failed` | auth | user_id, IP, reason (invalid_password, account_locked) |
| `auth.login_mfa_success` | auth | user_id, method (totp), IP, user_agent |
| `auth.login_mfa_failed` | auth | user_id, method (totp or recovery_code), IP |
| `auth.login_recovery_used` | auth | user_id, remaining_codes, IP, user_agent |
| `auth.logout` | auth | user_id, session_id |
| `auth.session_revoked` | auth | user_id, session_id |
| `auth.session_revoked_all` | auth | user_id |
| `auth.password_reset_requested` | auth | user_id, email |
| `auth.password_reset_completed` | auth | user_id |

**Delegate Events (5 actions):**

| Action | Category | Logged Detail |
| --- | --- | --- |
| `delegate.invited` | delegate | physician_id, delegate_email, permissions |
| `delegate.accepted` | delegate | physician_id, delegate_user_id, permissions |
| `delegate.permissions_updated` | delegate | physician_id, linkage_id, permissions, canApproveBatches |
| `delegate.revoked` | delegate | physician_id, delegate_user_id |
| `delegate.context_switched` | delegate | delegate_user_id, physician_user_id, linkage_id |

**Account Events (8 actions):**

| Action | Category | Logged Detail |
| --- | --- | --- |
| `account.updated` | account | user_id, fields changed |
| `account.mfa_reconfigured` | account | user_id |
| `account.recovery_codes_regenerated` | account | user_id |
| `account.deletion_requested` | account | user_id, scheduled_deletion_date, delegates_deactivated_count |
| `account.deletion_executed` | account | user_id, data_categories_deleted |
| `account.suspended` | account | user_id |
| `account.reactivated` | account | user_id |
| `account.secondary_email_updated` | account | user_id, old_email, new_email |

**Audit Events (2 actions):**

| Action | Category | Logged Detail |
| --- | --- | --- |
| `audit.queried` | audit | user_id, filters applied |
| `audit.exported` | audit | user_id, date range, format |

**Admin Events (1 action):**

| Action | Category | Logged Detail |
| --- | --- | --- |
| `admin.mfa_reset_issued` | admin | admin_id, target_user_id, justification |

## 6.2 Audit Log Query Requirements

Physicians can query their own audit log filtered by: date range, action, category. Scoped to userId — a physician can only see audit entries where they are the actor.

Delegates cannot view audit logs.

Admins can query system-wide audit logs with additional filters: user ID, action, category, date range.

Audit log queries are themselves logged (action: `audit.queried`) to prevent undetected surveillance.

Audit log entries are paginated (50 per page default, max 200). Returned in reverse chronological order.

Audit log export: Physician can export their own audit log as CSV (requires start_date and end_date). Admin can export system-wide. Exports are logged (action: `audit.exported`).

# 7. Security Requirements

These requirements are specific to the Identity & Access domain. System-wide security requirements are defined in the PRD (Section 11).

## 7.1 Credential Storage

Updated: All tech stack decisions from the original FRD have been resolved.

Passwords: Argon2id via `@node-rs/argon2` (native binding). Parameters: memory=19,456 KiB, iterations=2, parallelism=1. These parameters are defined as constants in the service layer (`ARGON2_OPTIONS`).

TOTP secrets: encrypted at rest using AES-256-GCM with a 32-byte key sourced from the `TOTP_ENCRYPTION_KEY` environment variable (hex-encoded). Storage format: `iv:authTag:ciphertext` (all hex-encoded). IV is 12 bytes (96 bits, GCM standard). Auth tag is 16 bytes (128 bits).

Recovery codes: Argon2id hashed (same parameters as passwords). Original codes shown once at generation and never stored or retrievable. Codes are normalised (dash-stripped, uppercased) before hashing and verification.

Session tokens: 32 random bytes (hex-encoded), stored as SHA-256 hashes in the sessions table. The plaintext token exists only in the HTTP-only cookie on the client.

Invitation tokens: UUID, stored as SHA-256 hashes. Plaintext exists only in the email link.

MFA session tokens: HMAC-SHA256 signed with `SESSION_SECRET`. Format: `base64url(payload).base64url(signature)`. Payload contains userId and expiry (5 minutes). Verified using constant-time comparison (`timingSafeEqual`).

## 7.2 Rate Limiting

Login attempts: 10 per email per 15-minute window. After limit, account locked for 30 minutes (enforced at DB level via `failed_login_count` and `locked_until` columns).

TOTP validation: Failed TOTP/recovery code attempts increment the same `failed_login_count`. 10 consecutive failures triggers 30-minute lock.

Password reset requests: Rate-limited at the route level via the auth rate limiter.

Registration: Rate-limited at the route level via the auth rate limiter.

API requests (authenticated): Default rate limit per CLAUDE.md (100 requests/minute per authenticated user).

## 7.3 Transport Security

All endpoints served over TLS (App Platform handles termination).

HSTS header with max-age=31536000, includeSubDomains, preload (via @fastify/helmet).

Session cookies: HttpOnly, Secure, SameSite=Lax, Path=/, Max-Age=86400.

CORS: restricted to meritum.ca origins only. No wildcard.

CSP headers enforced on all responses (via @fastify/helmet).

## 7.4 Input Validation

All input validation is performed by Zod schemas at the route layer (via fastify-type-provider-zod). Zod validation failures return 400 with structured error details.

Email: validated as `.string().email().max(255)`, normalised to lowercase.

Password: validated by `passwordSchema` — min 12 chars, regex requires at least one uppercase, one lowercase, one digit, one special character.

TOTP code: exactly 6 digits (string length 6, regex `^\d{6}$`).

Recovery code: string (normalised by the service layer).

Full name: 1–200 characters.

Phone: max 20 characters, optional.

Account deletion confirmation: `z.literal('DELETE')` — exact match required.

UUID parameters: All ID path parameters validated as `z.string().uuid()`.

All database operations use Drizzle ORM parameterised queries. No string concatenation in SQL.

## 7.5 Anti-Enumeration

Login failure message: "Invalid credentials" regardless of whether the email exists. A dummy Argon2id hash is performed when the email is not found to prevent timing-based enumeration.

Password reset: always returns success message regardless of email existence. Dummy hash performed for timing consistency.

Registration: anti-enumeration implemented — returns identical success response for both new and existing emails. A `USER_ALREADY_EXISTS` event is emitted so the notification service can warn the existing account holder. The existing user's ID is returned (indistinguishable from a new registration).

Response timing: constant-time comparison (`timingSafeEqual`) for MFA session token and session token validation.

# 8. Validation Rules

| Field | Rule | Error Message |
| --- | --- | --- |
| Email | RFC 5322 format (Zod `.email()`); max 255 chars; unique | Zod validation error |
| Password | ≥12 chars, ≥1 uppercase, ≥1 lowercase, ≥1 digit, ≥1 special char | "Password must be at least 12 characters" / "Password must contain uppercase, lowercase, digit, and special character" |
| Full name | 1–200 chars | Zod validation error |
| Phone | Max 20 chars; optional | Zod validation error |
| TOTP code | Exactly 6 digits (string) | "TOTP code must be exactly 6 digits" |
| Recovery code | String (normalised by service) | Business rule error on invalid code |
| Invitation email | Validated as email; max 255 chars | Zod validation error |
| Permissions (delegate) | Array of permission enum values; min 1 item; excludes `ADMIN_PHI_ACCESS` | Zod validation error / "Permission cannot be granted to delegates" |
| Account deletion confirmation | Exact literal "DELETE" | Zod validation error |
| Session ID param | UUID string | Zod validation error |
| Delegate ID param | UUID string | Zod validation error |
| Secondary email | Email format; max 100 chars; nullable | Zod validation error / "Secondary email must be different from primary email" |
| Audit log query dates | ISO 8601 date strings | Zod validation error |
| Audit log page | Integer, min 1, default 1 | Zod coerce + validation |
| Audit log page_size | Integer, min 1, max 200, default 50 | Zod coerce + validation |

# 9. Error Handling

All API errors return a consistent JSON structure: `{ error: { code: string, message: string, detail?: object } }`. HTTP status codes follow REST conventions.

| Scenario | HTTP Status | Error Code | User-Facing Message |
| --- | --- | --- | --- |
| Invalid credentials (email or password) | 422 | BUSINESS_RULE_VIOLATION | Invalid credentials |
| Invalid TOTP code | 422 | BUSINESS_RULE_VIOLATION | Invalid TOTP code |
| Account locked (too many attempts) | 422 | BUSINESS_RULE_VIOLATION | Account is temporarily locked. Please try again later. |
| Session expired / invalid | 401 | UNAUTHORIZED | Authentication required |
| Insufficient role | 403 | FORBIDDEN | Insufficient permissions |
| MFA setup required | 422 | BUSINESS_RULE_VIOLATION | MFA setup required before login |
| MFA session expired | 422 | BUSINESS_RULE_VIOLATION | Invalid or expired MFA session |
| Verification token invalid/expired | 422 | BUSINESS_RULE_VIOLATION | Invalid or expired verification token |
| Invitation expired | 422 | BUSINESS_RULE_VIOLATION | Invitation has expired |
| Invitation already accepted | 422 | BUSINESS_RULE_VIOLATION | Invitation has already been accepted |
| Delegate linkage not found | 422 | BUSINESS_RULE_VIOLATION | Delegate linkage not found |
| Forbidden delegate permission | 422 | BUSINESS_RULE_VIOLATION | Permission cannot be granted to delegates |
| Password verification failed (deletion) | 422 | BUSINESS_RULE_VIOLATION | Invalid password |
| Confirmation not "DELETE" | 422 | BUSINESS_RULE_VIOLATION | Confirmation must be exactly "DELETE" |
| Secondary email same as primary | 422 | BUSINESS_RULE_VIOLATION | Secondary email must be different from primary email |
| Account not found | 422 | BUSINESS_RULE_VIOLATION | Account not found |
| Validation error | 400 | VALIDATION_ERROR | Field-specific Zod errors |
| Server error | 500 | INTERNAL_ERROR | Internal server error (no details exposed) |
| IMA amendment pending | 403 | IMA_AMENDMENT_PENDING | You must acknowledge pending IMA amendments before continuing |

Design note: Business rule violations use HTTP 422 and `AppError` subclass `BusinessRuleError`. This distinguishes them from 400 validation errors (Zod schema failures) and 401/403 authentication/authorisation errors.

# 10. Interface Contracts with Other Domains

Identity & Access provides services to every other domain. These contracts define what data Identity & Access exposes and what events it emits.

## 10.1 Auth Context Object

Every authenticated API request carries an auth context object, populated by the auth middleware and available to all downstream domain handlers:

| Field | Type | Description |
| --- | --- | --- |
| userId | UUID | Authenticated user's ID |
| role | STRING | User's role (`PHYSICIAN`, `DELEGATE`, `ADMIN`, `PRACTICE_ADMIN`) |
| subscriptionStatus | STRING | Current subscription state (`TRIAL`, `ACTIVE`, `PAST_DUE`, `SUSPENDED`, `CANCELLED`) |
| sessionId | UUID | Current session ID (for audit logging) |
| delegateContext | OBJECT \| undefined | Present only when a delegate is acting under a physician's context |
| delegateContext.delegateUserId | UUID | The delegate's own user ID |
| delegateContext.physicianProviderId | UUID | The physician's user ID they are acting as |
| delegateContext.permissions | STRING[] | Permission keys for this physician-delegate linkage |
| delegateContext.linkageId | UUID | The delegate linkage record ID |

## 10.2 Events Emitted

Identity & Access emits events consumed by other domains (primarily Notification Service):

| Event | Payload | Consumer |
| --- | --- | --- |
| USER_REGISTERED | { userId, email, verificationToken } | Notification Service (verification email) |
| USER_ALREADY_EXISTS | { userId, email } | Notification Service (warn existing user) |
| MFA_SETUP_COMPLETE | { userId } | Onboarding (advance flow) |
| AUTH_LOGIN_SUCCESS | { userId, step } | Notification Service (optional security alert) |
| AUTH_LOGIN_MFA_SUCCESS | { userId, method } | Notification Service (optional new device alert) |
| AUTH_LOGIN_RECOVERY_USED | { userId, remainingCodes } | Notification Service (recovery code warning) |
| auth.session_revoked | { userId, sessionId } | Internal |
| auth.session_revoked_all | { userId, currentSessionId } | Internal |
| auth.logout | { userId, sessionId } | Internal |
| USER_PASSWORD_RESET_REQUESTED | { userId, email, resetToken } | Notification Service (reset email) |
| auth.password_reset_completed | { userId } | Internal |
| DELEGATE_INVITED | { physicianUserId, delegateEmail, invitationToken, permissions } | Notification Service (invitation email) |
| DELEGATE_ACCEPTED | { physicianUserId, delegateUserId, linkageId } | Notification Service (confirmation to physician) |
| DELEGATE_PERMISSIONS_UPDATED | { physicianUserId, linkageId, permissions, canApproveBatches } | Internal |
| DELEGATE_REVOKED | { physicianUserId, delegateUserId, linkageId } | Notification Service (notification to delegate) |
| DELEGATE_CONTEXT_SWITCHED | { delegateUserId, physicianUserId, linkageId } | Internal |
| ACCOUNT_UPDATED | { userId } | Internal |
| SUBSCRIPTION_CANCEL_REQUESTED | { userId } | Platform Operations (cancel Stripe subscription) |
| DELEGATE_ACCESS_REVOKED_ACCOUNT_DELETION | { delegateUserId, physicianUserId } | Notification Service (delegate notification) |
| ACCOUNT_DELETION_REQUESTED | { userId, scheduledDeletionDate } | All domains (prepare for data deletion) |
| RECOVERY_CODES_REGENERATED | { userId } | Internal |
| MFA_RECONFIGURED | { userId } | Internal |
| ACCOUNT_SECONDARY_EMAIL_UPDATED | { userId, oldEmail, newEmail } | Internal |

## 10.3 Provider Management Interface

Identity & Access creates the user record. Provider Management extends it with physician-specific data (PRAC ID, BA numbers, specialty, practice settings). The linkage is via user_id. Provider Management never duplicates auth data—it references the user record via foreign key.

When a delegate switches physician context (accessing a different physician's data), the auth middleware loads the appropriate delegate linkage and permission set. The `delegateContext` is set on the request context, and all downstream domain queries are scoped to that physician's data.

## 10.4 Platform Operations Interface

The Platform Operations domain manages IMA amendments and breach notifications. Domain 1 provides:

- **IMA amendment gating middleware**: Intercepts authenticated requests and blocks access if the physician has pending IMA amendments requiring response. This middleware is configured in the Platform Operations routes but uses Domain 1 auth context.
- **Secondary email for dual-delivery**: The `secondary_email` field on the users table is read by the Notification Service when sending IMA amendment and breach notifications. Both primary and secondary emails receive the notification.
- **PRACTICE_ADMIN role enforcement**: The role definition and permission keys for Practice Admin live in Domain 1 constants. Route-level enforcement uses `requireRole(Role.PRACTICE_ADMIN)`.

# 11. Testing Requirements

## 11.1 Unit Tests

Password hashing and validation (Argon2id with correct parameters)

TOTP generation, encryption (AES-256-GCM), and verification (including time drift tolerance of ±1 period)

Recovery code generation (character set, format), hashing (Argon2id), and single-use consumption

Session token generation (32 random bytes), SHA-256 hashing, expiry calculation (idle and absolute), and revocation

MFA session token generation (HMAC-SHA256), verification (constant-time comparison), and expiry

Permission checking logic (all role × permission combinations; forbidden delegate permissions)

Delegate context switching (correct physician_id scoping; active linkage verification)

Account lockout (counter increment, threshold trigger at 10, 30-minute lock)

Input validation for all fields (Zod schema positive and negative cases)

Subscription status access levels (TRIAL→full, ACTIVE→full, PAST_DUE→read_only, SUSPENDED→suspended, CANCELLED→suspended)

Anti-enumeration (registration with existing email; login with non-existent email; password reset with non-existent email)

Account deletion (three-factor confirmation; delegate deactivation; session revocation)

Secondary email (format validation; primary/secondary must differ; update and clear)

## 11.2 Integration Tests

Full registration → email verification → MFA setup → login flow

Password reset flow (request → token → reset → session invalidation → re-login)

Delegate invitation → acceptance → permission check → context switching

Delegate permission modification → immediate effect on next request

Delegate removal → immediate session invalidation

Stripe webhook processing → subscription status update → access gating

Account lock after failed attempts → unlock after timeout → successful login

Account deletion flow → grace period → data purge

Concurrent session management (multiple devices, selective revocation)

Secondary email update → dual-delivery verification

## 11.3 Security Tests

All 6 mandatory security test categories per CLAUDE.md:

**Authentication enforcement (authn):** 401 test for every route — register, verify-email, login, login/mfa, login/recovery, mfa/setup, mfa/confirm, logout, sessions (GET, DELETE /:id, DELETE), delegates (POST invite, GET, PATCH /:id/permissions, DELETE /:id, POST accept, GET physicians), account (GET, PATCH, POST mfa/regenerate-codes, POST mfa/reconfigure, POST delete, GET audit-log, PUT secondary-email).

**Authorisation (authz):** Permission tests for delegate management (Physician/Admin only), account deletion (Physician/Admin only), audit log (Physician/Admin only). Delegate role cannot access physician-only routes. Practice Admin cannot access claim/patient/analytics routes.

**Tenant isolation (scoping):** Delegates scoped to their physician context. Session revocation scoped to authenticated user. Audit log scoped to authenticated user.

**Input validation (input):** SQL injection payloads in email, name, phone fields. XSS payloads in name fields. Type coercion attacks. UUID format validation on all ID parameters.

**PHI leakage prevention (leakage):** Error responses do not echo credentials or tokens. 500 errors expose no internals. Server headers stripped.

**Audit trail (audit):** Every auth event produces an audit record. Audit log is append-only (no PUT/DELETE endpoints). Sensitive detail keys are redacted.

# 12. Open Questions for Tech Stack Selection

Updated: All open questions from v1.0 have been resolved during implementation.

| Question | Resolution |
| --- | --- |
| Session token format | Opaque tokens with PostgreSQL session store. Sessions stored as SHA-256 hashes in the `sessions` table. |
| Password hashing algorithm | Argon2id via `@node-rs/argon2` (native binding). Parameters: memory=19456 KiB, iterations=2, parallelism=1. |
| CSRF protection approach | SameSite=Lax cookies. No separate CSRF token at MVP. |
| Event bus for domain events | In-process event emitter. Functions call `events.emit()` directly. |
| Session store | PostgreSQL. Session lookup via `findSessionByTokenHash()` with expiry check at application layer. |

# 13. Document Control

Parent document: Meritum PRD v1.3

Domain: Identity & Access (Domain 1 of 13)

Build sequence position: 1st (no dependencies on other Meritum domains; depends on Stripe external service)

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 1.0 | February 12, 2026 | Ian Faulkner | Initial Identity & Access functional requirements |
| 2.0 | February 27, 2026 | Claude (automated FRD update) | Updated to reflect implementation: resolved all tech stack decisions (Argon2id, opaque sessions, PostgreSQL session store); added PRACTICE_ADMIN role and 4 practice management permissions; added secondary email for dual-delivery compliance notifications; added IMA amendment gating middleware and breach notification references; expanded audit action identifiers from 22 to 28; updated anti-enumeration approach for registration; added delegate context switching; corrected SameSite cookie attribute from Strict to Lax; updated error handling to use BusinessRuleError (HTTP 422); added MFA session token specification; added Platform Operations interface section |

| Depends On | Provides To | Interface Type |
| --- | --- | --- |
| Stripe (external) | All domains | Stripe webhooks → subscription status updates; Identity & Access gates platform access based on subscription state |
| Notification Service | Provider Management | Identity & Access emits events (registration, MFA setup, password reset, delegate invitation, IMA amendments, breach notifications) for Notification Service to deliver |
| — | Claim Lifecycle | Auth context (user ID, role, permissions, session ID) attached to every API request |
| — | Analytics & Reporting | Audit log data available for compliance reporting |
| — | All domains | Authorisation middleware: every API endpoint checks role + permissions via Identity & Access |
| — | Platform Operations | PRACTICE_ADMIN role definition; secondary email for dual-delivery; IMA amendment gating middleware |
