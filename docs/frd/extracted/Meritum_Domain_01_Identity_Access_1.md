# Meritum_Domain_01_Identity_Access_1

MERITUM

Functional Requirements

Identity & Access Domain

Domain 1 of 13  |  Critical Path: Position 1

Meritum Health Technologies Inc.

Version 1.0  |  February 2026

CONFIDENTIAL

# Table of Contents

# 1. Domain Overview

## 1.1 Purpose

The Identity & Access domain is the security perimeter of Meritum. It governs who can access the platform, how they authenticate, what they are authorised to do, and how all access is recorded. Every other domain depends on Identity & Access for authentication context and authorisation decisions.

This domain handles Protected Health Information (PHI) indirectly—it does not store clinical data, but it controls who can access clinical data stored in other domains. A failure in this domain is a failure of the entire platform’s security posture under the Health Information Act (HIA).

## 1.2 Scope

User registration (physician and admin accounts)

Authentication (email/password + mandatory TOTP MFA)

Session management (token lifecycle, expiry, revocation)

Role-based access control (RBAC): Physician, Delegate, Admin

Delegate management (invitation, permission scoping, batch approval authority)

Audit logging (all authentication and authorisation events)

Account lifecycle (password reset, MFA recovery, account suspension, account deletion)

Subscription status integration (Stripe webhook-driven access control)

## 1.3 Out of Scope

Stripe payment processing (Platform Operations domain)

Physician profile data beyond auth (Provider Management domain)

Patient data access decisions at the record level (Claim Lifecycle domain)

Notification delivery (Notification Service domain; Identity & Access emits events)

## 1.4 Domain Dependencies

# 2. Roles & Permissions Model

## 2.1 Role Definitions

## 2.2 Permission Matrix

Delegate permissions are configurable per Physician-Delegate relationship. A Delegate may serve multiple Physicians with different permission sets for each.

Design note: The Physician role is the data custodian under HIA. No other role can perform actions that the Physician has not explicitly authorised. The Delegate role exists to reduce administrative burden, not to operate independently. The Admin role is for platform operations and must not access PHI without Physician consent and audit trail.

# 3. User Stories & Acceptance Criteria

## 3.1 Registration & Onboarding

## 3.2 Authentication

## 3.3 Delegate Management

## 3.4 Account Lifecycle

# 4. Data Model

All timestamps are stored in UTC. All IDs are UUIDs (v4). Sensitive fields (password, TOTP secret, recovery codes) are hashed before storage and never returned in API responses.

## 4.1 Users Table

## 4.2 Recovery Codes Table

## 4.3 Sessions Table

## 4.4 Delegate Linkages Table

## 4.5 Invitation Tokens Table

## 4.6 Audit Log Table

Retention: Audit logs are retained for 7 years per HIA record-keeping requirements. Logs are append-only—no row may be updated or deleted. The audit log table should be partitioned by month for query performance.

# 5. API Contracts

All endpoints use JSON request/response bodies. All responses include appropriate HTTP status codes. All endpoints (except registration, login, and password reset) require a valid session token. All requests are logged in the audit trail.

## 5.1 Authentication Endpoints

## 5.2 Session Endpoints

## 5.3 Delegate Management Endpoints

## 5.4 Account Management Endpoints

## 5.5 Auth Middleware (Internal)

Every API endpoint (except those marked “No” auth) passes through authentication and authorisation middleware:

authenticate(): Validates session token from HTTP-only cookie. Checks absolute and idle expiry. Refreshes idle timer on success. Returns 401 Unauthorized if invalid/expired.

authorize(requiredRole, requiredPermission?): Checks user role against required role. For delegates, also checks the specific permission for the requested physician’s data. Returns 403 Forbidden if insufficient permissions.

checkSubscription(): Checks subscription status. Returns 402 Payment Required with details if account is suspended. Allows read-only access for suspended/cancelled accounts per IAM-011/IAM-013.

auditLog(action, detail): Automatically appends an audit log entry for every API request. Middleware-level logging ensures no endpoint can bypass audit.

# 6. Audit Log Specification

The audit log is the compliance backbone of Meritum under HIA. Every access event, state change, and administrative action is recorded. The audit log is append-only, immutable, and retained for 7 years.

## 6.1 Action Identifiers

## 6.2 Audit Log Query Requirements

Physicians can query their own audit log filtered by: date range, action category, action type.

Delegates cannot view audit logs.

Admins can query system-wide audit logs with additional filters: user ID, IP address, action category.

Audit log queries are themselves logged (action: “audit.queried”) to prevent undetected surveillance.

Audit log entries are paginated (50 per page default, max 200). Returned in reverse chronological order.

Audit log export: Physician can export their own audit log as CSV. Admin can export system-wide. Exports are logged.

# 7. Security Requirements

These requirements are specific to the Identity & Access domain. System-wide security requirements are defined in the PRD (Section 11).

## 7.1 Credential Storage

Passwords: bcrypt with cost factor ≥12, or Argon2id (memory=64MB, iterations=3, parallelism=1). Decision during tech stack selection.

TOTP secrets: encrypted at rest using AES-256-GCM with a key managed via the platform’s secrets management system. The encryption key is not stored in the database.

Recovery codes: bcrypt hashed (same parameters as passwords). Original codes shown once at generation and never stored or retrievable.

Session tokens: stored as SHA-256 hashes in the sessions table. The plaintext token exists only in the HTTP-only cookie on the client.

Invitation tokens: stored as SHA-256 hashes. Plaintext exists only in the email link.

## 7.2 Rate Limiting

Login attempts: 10 per email per 15-minute window. After limit, account locked for 30 minutes.

TOTP validation: 5 consecutive failures triggers 15-minute lock.

Password reset requests: 3 per email per hour (silent rate limit; always returns success message).

Registration: 5 per IP per hour.

API requests (authenticated): 1000 per user per minute (generous for normal use; prevents abuse).

## 7.3 Transport Security

All endpoints served over TLS 1.3 only. TLS 1.2 accepted as fallback. TLS 1.1 and below rejected.

HSTS header with max-age=31536000, includeSubDomains, preload.

Session cookies: HttpOnly, Secure, SameSite=Strict, Path=/, Domain=meritum.ca.

CORS: restricted to meritum.ca origins only. No wildcard.

CSP headers enforced on all responses.

## 7.4 Input Validation

Email: validated against RFC 5322 format, normalised to lowercase, max 255 characters.

Password: validated server-side against all requirements (IAM-001). Client-side validation is a UX convenience, not a security control.

TOTP code: exactly 6 digits. No other input accepted.

Recovery code: exactly 8 alphanumeric characters.

All text fields: sanitised for XSS. Parameterised queries for all database operations (no string concatenation in SQL).

## 7.5 Anti-Enumeration

Login failure message: “Invalid email or password” regardless of whether the email exists.

Password reset: always returns “If an account exists, a reset link has been sent” regardless of email existence.

Registration: if email already exists, display “An account with this email already exists” (this is an acceptable trade-off for UX; the alternative is silent registration with a “check your email” message for all cases).

Response timing: constant-time comparison for password and TOTP validation to prevent timing attacks.

# 8. Validation Rules

# 9. Error Handling

All API errors return a consistent JSON structure: { error: { code: string, message: string, detail?: object } }. HTTP status codes follow REST conventions.

# 10. Interface Contracts with Other Domains

Identity & Access provides services to every other domain. These contracts define what data Identity & Access exposes and what events it emits.

## 10.1 Auth Context Object

Every authenticated API request carries an auth context object, populated by the auth middleware and available to all downstream domain handlers:

## 10.2 Events Emitted

Identity & Access emits events consumed by other domains (primarily Notification Service):

## 10.3 Provider Management Interface

Identity & Access creates the user record. Provider Management extends it with physician-specific data (PRAC ID, BA numbers, specialty, practice settings). The linkage is via user_id. Provider Management never duplicates auth data—it references the user record via foreign key.

When a delegate switches physician context (accessing a different physician’s data), the auth middleware loads the appropriate delegate linkage and permission set. The acting_as_physician_id is set on the request context, and all downstream domain queries are scoped to that physician’s data.

# 11. Testing Requirements

## 11.1 Unit Tests

Password hashing and validation (all requirement combinations)

TOTP generation and validation (including time drift tolerance of ±1 period)

Recovery code generation, hashing, and single-use consumption

Session token generation, expiry calculation (idle and absolute), and revocation

Permission checking logic (all role × permission × resource combinations)

Delegate context switching (correct physician_id scoping)

Rate limiting logic (counter increment, reset, lock trigger)

Input validation for all fields (valid and invalid cases)

Subscription status gating (all status × action combinations)

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

## 11.3 Security Tests

Timing attack resistance on login (constant-time comparison)

Session fixation prevention (new token on login, not reuse)

CSRF protection (SameSite cookie + CSRF token for state-changing requests)

XSS prevention (all user-generated content sanitised)

SQL injection prevention (parameterised queries for all database access)

Rate limiting enforcement under load

Session cookie attributes (HttpOnly, Secure, SameSite verified)

TOTP brute force protection (lockout after 5 failures)

Enumeration resistance (login, password reset, registration response timing and content)

Horizontal privilege escalation (delegate accessing another physician’s data without linkage)

Vertical privilege escalation (delegate performing physician-only actions)

# 12. Open Questions for Tech Stack Selection

# 13. Document Control

Parent document: Meritum PRD v1.3

Domain: Identity & Access (Domain 1 of 13)

Build sequence position: 1st (no dependencies on other Meritum domains; depends on Stripe external service)

| Depends On | Provides To | Interface Type |
| --- | --- | --- |
| Stripe (external) | All domains | Stripe webhooks → subscription status updates; Identity & Access gates platform access based on subscription state |
| Notification Service | Provider Management | Identity & Access emits events (registration, MFA setup, password reset, delegate invitation) for Notification Service to deliver |
| — | Claim Lifecycle | Auth context (user ID, role, permissions, associated BA numbers) attached to every API request |
| — | Analytics & Reporting | Audit log data available for compliance reporting |
| — | All domains | Authorisation middleware: every API endpoint checks role + resource-level permissions via Identity & Access |

| Role | Description | Created By |
| --- | --- | --- |
| Physician | Primary account holder. Full access to all data and features under their BA number(s). Can manage delegates, configure submission preferences, approve batches, export data, manage subscription. | Self-registration |
| Delegate | Granted access by a Physician. Scoped to one or more Physician accounts. Permissions are configurable per Physician. Cannot create their own account independently—must be invited by a Physician. | Physician invitation |
| Admin | Platform administrator (Ian initially). System-wide access for support, configuration, and monitoring. Cannot access PHI unless explicitly granted by a Physician for support purposes (logged and time-limited). | System provisioned |

| Permission | Physician | Delegate (Configurable) | Admin |
| --- | --- | --- | --- |
| View own claims | Always | Granted by default | Support access only (logged, time-limited) |
| Create/edit claims | Always | Granted by default | Never |
| Delete draft claims | Always | Granted by default | Never |
| Submit claims (queue for batch) | Always | Granted by default | Never |
| Approve batch submission | Always | Configurable (batch approval authority) | Never |
| View rejections | Always | Granted by default | Never |
| Resubmit rejected claims | Always | Configurable | Never |
| Import claims (CSV/EMR batch) | Always | Configurable | Never |
| View patient registry | Always | Granted by default | Never |
| Add/edit patients | Always | Configurable | Never |
| Import patients (CSV) | Always | Configurable | Never |
| View analytics/dashboard | Always | Configurable | System-level only |
| Export reports (accountant/CSV/PDF) | Always | Configurable | Never |
| Download all data (data portability) | Always | Never | Never |
| Manage delegates | Always | Never | Never |
| Configure submission preferences | Always | Never | Never |
| Manage subscription/billing | Always | Never | Never |
| View audit log (own account) | Always | Never | System-wide |
| Sign IMA / download PIA | Always | Never | Never |
| Configure notification preferences | Always | Own preferences only | System-level |
| Access admin panel | Never | Never | Always |
| View system health/metrics | Never | Never | Always |
| Manage reference data updates | Never | Never | Always |
| Manage platform configuration | Never | Never | Always |

| IAM-001 | Physician Registration |
| --- | --- |
| User Story | As a physician, I want to create a Meritum account so that I can begin setting up my billing profile. |
| Acceptance Criteria | • Registration form collects: full name, email address, password, and mobile phone number (for MFA recovery). • Email address must be unique across the platform. If already registered, display “An account with this email already exists” without revealing whether the account is active (prevents enumeration). • Password must meet minimum requirements: ≥12 characters, ≥1 uppercase, ≥1 lowercase, ≥1 digit, ≥1 special character. Password strength indicator displayed in real-time. • Password is hashed using bcrypt (cost factor ≥12) or Argon2id before storage. Plaintext password is never stored or logged. • On successful registration, a verification email is sent to the provided address. Account is in “unverified” state until email is confirmed. • Email verification link expires after 24 hours. A “Resend verification” option is available. • After email verification, the user is immediately prompted to set up TOTP MFA (see IAM-002). MFA setup is mandatory—the account cannot be used until MFA is configured. • Registration event is logged in the audit trail: timestamp, email (hashed), IP address, user agent. • Account is created in “pending_subscription” state. Access to billing features is gated until Stripe subscription is active. |

| IAM-002 | Mandatory MFA Setup |
| --- | --- |
| User Story | As a newly registered physician, I want to set up two-factor authentication so that my account is protected against credential compromise. |
| Acceptance Criteria | • After email verification, the user is presented with a TOTP setup screen showing a QR code and a manual entry key. • The TOTP secret is generated server-side using a cryptographically secure random number generator. Secret length: 160 bits minimum. • QR code encodes the otpauth:// URI with issuer=“Meritum”, account=user’s email, algorithm=SHA1, digits=6, period=30s. • User must enter a valid TOTP code from their authenticator app to confirm setup. The system verifies the code before activating MFA. • Upon successful MFA setup, the system generates 10 single-use recovery codes (8 alphanumeric characters each). These are displayed once and must be acknowledged by the user (“I have saved these codes” checkbox). • Recovery codes are stored hashed (bcrypt). They cannot be retrieved—only regenerated (which invalidates all previous codes). • MFA setup event is logged: timestamp, user ID, method (TOTP), IP address. • Account transitions from “unverified” to “active” (or “pending_subscription” if subscription not yet active). |

| IAM-003 | Delegate Invitation |
| --- | --- |
| User Story | As a physician, I want to invite a delegate (e.g., my office administrator) to access my billing on my behalf so that I can share the workload without sharing my credentials. |
| Acceptance Criteria | • Physician enters the delegate’s email address and selects permissions from the configurable permission set (see Section 2.2). • System sends an invitation email with a unique, single-use invitation token (expires after 72 hours). • If the delegate already has a Meritum account (as a delegate for another physician), they can accept the invitation and add this physician to their existing account. No new registration required. • If the delegate does not have an account, clicking the invitation link opens a registration form (name, email pre-filled, password, phone). MFA setup is mandatory for delegates as well. • On acceptance, the Delegate’s account is linked to the Physician’s account with the configured permissions. • A Delegate can be linked to multiple Physicians. Each linkage has its own independent permission set. • Physician can view all active delegates, their permission sets, and their last login time. • Invitation event logged: timestamp, physician ID, delegate email (hashed), permissions granted, IP address. • Acceptance event logged: timestamp, delegate user ID, physician ID, IP address. |

| IAM-004 | Login |
| --- | --- |
| User Story | As a registered user, I want to log in to Meritum so that I can access my billing features. |
| Acceptance Criteria | • User enters email and password on the login form. • If credentials are valid, the system prompts for TOTP code (second factor). • If TOTP code is valid, a session is created and the user is redirected to their dashboard. • If email/password is invalid, display “Invalid email or password” (do not indicate which field is wrong). • If TOTP code is invalid, display “Invalid verification code” and allow retry. After 5 consecutive failed TOTP attempts, the account is temporarily locked for 15 minutes. • After 10 consecutive failed login attempts (password stage), the account is temporarily locked for 30 minutes. A notification email is sent to the account holder. • Successful login creates a session token (see IAM-006). Login event logged: timestamp, user ID, IP address, user agent, success/failure. • Failed login event logged: timestamp, email (hashed), IP address, user agent, failure reason (invalid_password, invalid_totp, account_locked). • If the account is in “suspended” state (e.g., payment failure), login succeeds but access is restricted to account management and data export only. A banner explains the suspension reason. |

| IAM-005 | MFA Recovery |
| --- | --- |
| User Story | As a user who has lost access to my authenticator app, I want to use a recovery code to log in so that I am not permanently locked out. |
| Acceptance Criteria | • After entering valid email/password, the user clicks “Use recovery code” instead of entering a TOTP code. • User enters one of their 10 single-use recovery codes. • If valid, the recovery code is consumed (marked as used, cannot be reused). Login proceeds normally. • After successful recovery login, the user is prompted (but not forced) to reconfigure TOTP with a new secret. A warning is displayed showing how many recovery codes remain. • If all 10 recovery codes are exhausted and the user has lost their authenticator, the account enters a manual recovery process: user contacts support, identity is verified via the email and phone on file, and an Admin can issue a time-limited MFA reset token (logged with justification). • Recovery code usage logged: timestamp, user ID, IP address. Recovery code regeneration logged: timestamp, user ID, IP address. • Admin-assisted MFA reset logged: timestamp, admin ID, user ID, justification, IP address. |

| IAM-006 | Session Management |
| --- | --- |
| User Story | As a logged-in user, I want my session to be secure and expire after a reasonable period of inactivity so that my account is protected if I forget to log out. |
| Acceptance Criteria | • On successful authentication, the server issues a session token (JWT or opaque token, decision during tech stack selection). • Session token has two expiry parameters: absolute expiry (24 hours from creation) and idle expiry (60 minutes of inactivity). Whichever is reached first invalidates the session. • Session token is transmitted via HTTP-only, Secure, SameSite=Strict cookie. Never stored in localStorage or sessionStorage. • Each API request validates the session token and refreshes the idle expiry timer (sliding window). • User can explicitly log out, which invalidates the session server-side immediately. • User can view active sessions (device, IP, last activity) and revoke any session remotely (“Log out of all devices”). • Session creation and destruction events logged: timestamp, user ID, IP address, user agent, reason (login, logout, expired_idle, expired_absolute, revoked). • Concurrent sessions are allowed (physician may be logged in on desktop and mobile). No upper limit at MVP, but each session is independently tracked and revocable. |

| IAM-007 | Password Reset |
| --- | --- |
| User Story | As a user who has forgotten my password, I want to reset it securely so that I can regain access to my account. |
| Acceptance Criteria | • User enters their email on the password reset form. • System always responds with “If an account with that email exists, a reset link has been sent” (prevents enumeration). • If the account exists, a password reset email is sent with a single-use token that expires after 1 hour. • Clicking the link opens a form to set a new password. Same password requirements as registration (IAM-001). • On successful reset, all existing sessions for the user are invalidated (forced re-login). • The user must re-authenticate with the new password + TOTP to access the platform. • Password reset request logged: timestamp, email (hashed), IP address. Password reset completion logged: timestamp, user ID, IP address. |

| IAM-008 | Delegate Permission Modification |
| --- | --- |
| User Story | As a physician, I want to modify my delegate’s permissions so that I can adjust their access as our working relationship evolves. |
| Acceptance Criteria | • Physician navigates to delegate management and selects a delegate. • All configurable permissions (Section 2.2) are displayed with current state (granted/denied). • Physician can toggle any configurable permission. Changes take effect immediately on next API request from the delegate. • A summary of changes is displayed for confirmation before saving. • Permission change event logged: timestamp, physician ID, delegate ID, permissions changed (old → new), IP address. • If the delegate is currently logged in, their next API request will reflect the updated permissions. No active session invalidation required (permissions checked on each request, not baked into token). |

| IAM-009 | Delegate Removal |
| --- | --- |
| User Story | As a physician, I want to remove a delegate’s access to my account so that they can no longer view or manage my billing. |
| Acceptance Criteria | • Physician selects a delegate and clicks “Remove access.” Confirmation dialog: “This will immediately revoke [name]’s access to your account. This cannot be undone—you would need to send a new invitation.” • On confirmation, the Delegate’s linkage to this Physician is deactivated. All active sessions for this Delegate (for this Physician’s data) are invalidated immediately. • If the Delegate serves other Physicians, their access to those accounts is unaffected. • If the Delegate serves no other Physicians after removal, their account remains active but has no accessible data. They can be re-invited by any Physician in the future. • Removal event logged: timestamp, physician ID, delegate ID, IP address. • A notification email is sent to the delegate informing them that their access has been revoked. |

| IAM-010 | Batch Approval Authority |
| --- | --- |
| User Story | As a physician, I want to grant my delegate the authority to approve claim batches on my behalf so that submissions are not delayed when I’m unavailable. |
| Acceptance Criteria | • Batch approval authority is a specific permission in the delegate permission set (Section 2.2, “Approve batch submission”). • When granted, the delegate can access the pre-submission review screen and approve or hold flagged claims for the physician’s account. • The delegate’s approval is functionally equivalent to the physician’s for submission purposes. • All delegate batch approvals are logged with: timestamp, delegate ID, physician ID, batch ID, number of claims approved, number of claims held, IP address. • The physician receives a notification when a delegate approves a batch on their behalf: “[Delegate name] approved [X] claims for submission on your behalf.” • Batch approval authority can be granted and revoked at any time via delegate permission management (IAM-008). |

| IAM-011 | Account Suspension (Payment Failure) |
| --- | --- |
| User Story | As the system, I want to suspend accounts with failed payments so that access is gated behind active subscription, while ensuring physicians can still access their data. |
| Acceptance Criteria | • When Stripe webhook reports subscription_past_due (after dunning sequence: retry at days 1, 3, 7), account transitions to “suspended” state. • Suspended accounts can still: log in, view existing claims and analytics (read-only), export data (data portability), update payment method via Stripe customer portal, view invoices. • Suspended accounts cannot: create new claims, import claims, submit batches, access AI Coach, invite delegates. • A prominent banner is displayed on all screens: “Your subscription payment has failed. Please update your payment method to restore full access. Your data is safe and accessible.” • If payment is not resolved within 14 days of first failure, a final notification is sent: “Your account will be deactivated in 7 days if payment is not updated. All your data will remain exportable for 90 days after deactivation.” • If payment is resolved (Stripe webhook: invoice.paid), account immediately transitions back to “active”. No data loss, no re-onboarding. • Suspension and reactivation events logged: timestamp, user ID, reason, Stripe event ID. |

| IAM-012 | Account Deletion |
| --- | --- |
| User Story | As a physician, I want to delete my account so that my data is removed from the platform when I no longer need it. |
| Acceptance Criteria | • Physician navigates to account settings and selects “Delete my account.” • A multi-step confirmation process: (1) display warning with consequences, (2) require password entry, (3) require TOTP code, (4) type “DELETE” to confirm. • Before deletion, the system forces a complete data export and download (data portability). The physician must acknowledge they have downloaded their data or explicitly decline. • On confirmation: all active sessions invalidated, all delegate linkages deactivated (delegates notified), Stripe subscription cancelled. • PHI data is scheduled for permanent deletion after a 30-day grace period. During the grace period, the physician can contact support to reverse the deletion (account reactivated, data restored). • After 30 days, all PHI is permanently deleted: claims, patient records, audit logs containing PHI. Non-PHI records (anonymised usage metrics, financial records required for tax purposes) are retained per legal requirements. • Deletion request logged: timestamp, user ID, IP address. Deletion execution logged: timestamp, system process, data categories deleted. |

| IAM-013 | Subscription-Gated Access |
| --- | --- |
| User Story | As the system, I want to gate feature access based on subscription status so that only paying users can submit claims. |
| Acceptance Criteria | • Stripe webhooks update account subscription status in real-time: active, trialing, past_due, suspended, cancelled. • Access tiers based on subscription status: “active” and “trialing” = full access; “past_due” = full access for 7 days then suspension warning; “suspended” = read-only + data export; “cancelled” = read-only + data export for 90 days then deactivation. • Subscription status is cached locally (not checked against Stripe on every request). Webhook events update the local cache. Cache TTL: check Stripe directly if local status is >1 hour old as a fallback. • Free month for referred physicians: account created in “trialing” state for 30 days, then transitions to “active” when first payment succeeds. • Early bird pricing is a Stripe plan variant. No application-level logic needed beyond passing the correct plan ID at subscription creation. • Subscription status change events logged: timestamp, user ID, old status, new status, Stripe event ID. |

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| id | UUID | PK | Primary identifier |
| email | VARCHAR(255) | UNIQUE, NOT NULL | Login identifier; lowercase normalised |
| email_verified | BOOLEAN | NOT NULL, DEFAULT false | Set true on email verification |
| password_hash | VARCHAR(255) | NOT NULL | bcrypt (cost ≥12) or Argon2id |
| full_name | VARCHAR(255) | NOT NULL | Display name |
| phone | VARCHAR(20) | NOT NULL | For MFA recovery; E.164 format |
| role | ENUM | NOT NULL | physician, delegate, admin |
| mfa_secret_encrypted | VARCHAR(255) | NOT NULL after MFA setup | TOTP secret; encrypted at rest (AES-256) |
| mfa_configured | BOOLEAN | NOT NULL, DEFAULT false | True after successful MFA setup |
| subscription_status | ENUM | NOT NULL, DEFAULT pending_subscription | pending_subscription, active, trialing, past_due, suspended, cancelled |
| stripe_customer_id | VARCHAR(255) | UNIQUE, NULLABLE | Stripe customer reference |
| account_status | ENUM | NOT NULL, DEFAULT unverified | unverified, active, suspended, deactivated, pending_deletion |
| failed_login_attempts | INTEGER | NOT NULL, DEFAULT 0 | Reset on successful login |
| locked_until | TIMESTAMP | NULLABLE | Account lock expiry after failed attempts |
| created_at | TIMESTAMP | NOT NULL | Registration timestamp |
| updated_at | TIMESTAMP | NOT NULL | Last modification |
| last_login_at | TIMESTAMP | NULLABLE | Last successful login |
| deletion_requested_at | TIMESTAMP | NULLABLE | 30-day grace period start |

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| id | UUID | PK |  |
| user_id | UUID | FK → users.id, NOT NULL |  |
| code_hash | VARCHAR(255) | NOT NULL | bcrypt hash of recovery code |
| used | BOOLEAN | NOT NULL, DEFAULT false | Set true on use; cannot be reused |
| created_at | TIMESTAMP | NOT NULL | Regeneration invalidates all previous codes |

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| id | UUID | PK | Session identifier (token reference) |
| user_id | UUID | FK → users.id, NOT NULL |  |
| token_hash | VARCHAR(255) | NOT NULL | Hash of session token (token itself only in cookie) |
| ip_address | INET | NOT NULL | Client IP at session creation |
| user_agent | TEXT | NOT NULL | Browser/device identification |
| created_at | TIMESTAMP | NOT NULL | Absolute expiry = created_at + 24h |
| last_active_at | TIMESTAMP | NOT NULL | Idle expiry = last_active_at + 60min |
| revoked | BOOLEAN | NOT NULL, DEFAULT false | Set true on logout or remote revocation |
| revoked_reason | ENUM | NULLABLE | logout, expired_idle, expired_absolute, revoked_remote, password_reset, account_deleted |

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| id | UUID | PK |  |
| physician_user_id | UUID | FK → users.id, NOT NULL | The physician granting access |
| delegate_user_id | UUID | FK → users.id, NOT NULL | The delegate receiving access |
| permissions | JSONB | NOT NULL | Permission set as key-value pairs; see Section 2.2 |
| active | BOOLEAN | NOT NULL, DEFAULT true | Set false on removal (soft delete for audit) |
| invited_at | TIMESTAMP | NOT NULL |  |
| accepted_at | TIMESTAMP | NULLABLE | NULL until invitation accepted |
| deactivated_at | TIMESTAMP | NULLABLE |  |
| UNIQUE |  | (physician_user_id, delegate_user_id) | One linkage per physician-delegate pair |

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| id | UUID | PK |  |
| physician_user_id | UUID | FK → users.id, NOT NULL | Who sent the invitation |
| delegate_email | VARCHAR(255) | NOT NULL | Invitee email |
| token_hash | VARCHAR(255) | NOT NULL | Hash of invitation token |
| permissions | JSONB | NOT NULL | Intended permissions on acceptance |
| expires_at | TIMESTAMP | NOT NULL | 72 hours from creation |
| accepted | BOOLEAN | NOT NULL, DEFAULT false |  |
| created_at | TIMESTAMP | NOT NULL |  |

| Field | Type | Constraints | Notes |
| --- | --- | --- | --- |
| id | UUID | PK | Append-only; no UPDATE or DELETE permitted |
| timestamp | TIMESTAMP | NOT NULL | Event occurrence time (UTC) |
| user_id | UUID | NULLABLE (FK → users.id) | NULL for anonymous events (failed login with unknown email) |
| actor_type | ENUM | NOT NULL | user, system, admin |
| action | VARCHAR(100) | NOT NULL | Structured action identifier (see Section 6) |
| resource_type | VARCHAR(50) | NULLABLE | user, session, delegate_linkage, invitation, etc. |
| resource_id | UUID | NULLABLE | ID of affected resource |
| detail | JSONB | NULLABLE | Additional context (permissions changed, failure reason, etc.) |
| ip_address | INET | NULLABLE | Client IP |
| user_agent | TEXT | NULLABLE | Browser/device |
| physician_id | UUID | NULLABLE (FK → users.id) | For delegate actions: which physician’s data was accessed |

| Method | Endpoint | Description | Auth Required |
| --- | --- | --- | --- |
| POST | /api/v1/auth/register | Create new physician account. Body: { email, password, full_name, phone }. Returns: { user_id, email_verification_required: true }. | No |
| POST | /api/v1/auth/verify-email | Verify email with token. Body: { token }. Returns: { mfa_setup_required: true }. | No |
| POST | /api/v1/auth/mfa/setup | Initiate MFA setup. Returns: { qr_code_uri, manual_key }. Requires valid email-verified session. | Partial (email-verified) |
| POST | /api/v1/auth/mfa/confirm | Confirm MFA with first TOTP code. Body: { totp_code }. Returns: { recovery_codes: [...] }. | Partial |
| POST | /api/v1/auth/login | Step 1: email/password. Body: { email, password }. Returns: { mfa_required: true, mfa_session_token }. | No |
| POST | /api/v1/auth/login/mfa | Step 2: TOTP code. Body: { mfa_session_token, totp_code }. Returns: { session_token } (set as HTTP-only cookie). | No |
| POST | /api/v1/auth/login/recovery | Step 2 alt: recovery code. Body: { mfa_session_token, recovery_code }. Returns: { session_token, remaining_codes: N }. | No |
| POST | /api/v1/auth/logout | Invalidate current session. | Yes |
| POST | /api/v1/auth/password/reset-request | Request password reset. Body: { email }. Always returns 200. | No |
| POST | /api/v1/auth/password/reset | Reset password with token. Body: { token, new_password }. Invalidates all sessions. | No |

| Method | Endpoint | Description | Auth Required |
| --- | --- | --- | --- |
| GET | /api/v1/sessions | List active sessions for current user. Returns: [{ id, ip_address, user_agent, created_at, last_active_at }]. | Yes |
| DELETE | /api/v1/sessions/:id | Revoke a specific session. | Yes |
| DELETE | /api/v1/sessions | Revoke all sessions except current (“Log out everywhere”). | Yes |

| Method | Endpoint | Description | Auth Required |
| --- | --- | --- | --- |
| POST | /api/v1/delegates/invite | Invite a delegate. Body: { email, permissions }. Returns: { invitation_id }. | Yes (Physician) |
| GET | /api/v1/delegates | List all delegates for the current physician. Returns: [{ delegate_id, name, email, permissions, last_login, active }]. | Yes (Physician) |
| PATCH | /api/v1/delegates/:id/permissions | Update delegate permissions. Body: { permissions }. Returns: updated permission set. | Yes (Physician) |
| DELETE | /api/v1/delegates/:id | Remove delegate access. Invalidates delegate’s sessions for this physician. | Yes (Physician) |
| POST | /api/v1/delegates/accept | Accept invitation. Body: { token } (+ registration fields if new user). Returns: { linkage_id }. | No (creates or links account) |
| GET | /api/v1/delegates/physicians | List physicians the current delegate serves. Returns: [{ physician_id, name, permissions }]. | Yes (Delegate) |

| Method | Endpoint | Description | Auth Required |
| --- | --- | --- | --- |
| GET | /api/v1/account | Get current user account info (name, email, role, subscription_status, mfa_configured). | Yes |
| PATCH | /api/v1/account | Update account fields (name, phone). Email change requires re-verification. | Yes |
| POST | /api/v1/account/mfa/regenerate-codes | Regenerate recovery codes. Requires TOTP confirmation. Invalidates all previous codes. | Yes |
| POST | /api/v1/account/mfa/reconfigure | Reconfigure TOTP (new secret). Requires current TOTP code. Returns new QR + recovery codes. | Yes |
| POST | /api/v1/account/delete | Request account deletion. Body: { password, totp_code, confirmation: “DELETE” }. | Yes (Physician) |
| GET | /api/v1/account/audit-log | Paginated audit log for current user. Filters: action, date range. Returns: [AuditLogEntry]. | Yes (Physician + Admin) |

| Action | Category | Logged Detail |
| --- | --- | --- |
| auth.register | Authentication | email (hashed), IP, user_agent |
| auth.verify_email | Authentication | user_id, IP |
| auth.mfa_setup | Authentication | user_id, method (TOTP), IP |
| auth.login_success | Authentication | user_id, IP, user_agent |
| auth.login_failure | Authentication | email (hashed), IP, user_agent, reason |
| auth.login_recovery_code | Authentication | user_id, IP, remaining_codes |
| auth.logout | Authentication | user_id, session_id, IP |
| auth.password_reset_request | Authentication | email (hashed), IP |
| auth.password_reset_complete | Authentication | user_id, IP, sessions_invalidated_count |
| auth.account_locked | Authentication | user_id, lock_duration, IP |
| session.created | Session | user_id, session_id, IP, user_agent |
| session.expired | Session | user_id, session_id, reason (idle/absolute) |
| session.revoked | Session | user_id, session_id, revoked_by (self/remote/password_reset) |
| delegate.invited | Delegate | physician_id, delegate_email (hashed), permissions |
| delegate.accepted | Delegate | physician_id, delegate_user_id, IP |
| delegate.permissions_changed | Delegate | physician_id, delegate_id, old_permissions, new_permissions |
| delegate.removed | Delegate | physician_id, delegate_id |
| delegate.batch_approved | Delegate | physician_id, delegate_id, batch_id, claims_approved, claims_held |
| account.updated | Account | user_id, fields_changed |
| account.mfa_reconfigured | Account | user_id, IP |
| account.mfa_codes_regenerated | Account | user_id, IP |
| account.deletion_requested | Account | user_id, IP |
| account.deletion_executed | Account | user_id, data_categories_deleted |
| account.deletion_reversed | Account | user_id, admin_id, IP |
| subscription.status_changed | Subscription | user_id, old_status, new_status, stripe_event_id |
| admin.mfa_reset | Admin | admin_id, target_user_id, justification, IP |
| admin.phi_access_granted | Admin | admin_id, physician_id, reason, expiry, IP |
| admin.account_reactivated | Admin | admin_id, target_user_id, reason, IP |

| Field | Rule | Error Message |
| --- | --- | --- |
| Email | RFC 5322 format; max 255 chars; unique | “Please enter a valid email address” / “An account with this email already exists” |
| Password | ≥12 chars, ≥1 uppercase, ≥1 lowercase, ≥1 digit, ≥1 special char | “Password must be at least 12 characters with uppercase, lowercase, number, and special character” |
| Password | Not in top 100,000 common passwords list | “This password is too common. Please choose a stronger password.” |
| Full name | 2–255 chars; letters, spaces, hyphens, apostrophes only | “Please enter a valid name” |
| Phone | E.164 format (e.g., +14035551234); 10–15 digits | “Please enter a valid phone number including country code” |
| TOTP code | Exactly 6 digits | “Verification code must be 6 digits” |
| Recovery code | Exactly 8 alphanumeric characters | “Recovery code must be 8 characters” |
| Invitation email | RFC 5322 format; cannot be the physician’s own email | “You cannot invite yourself as a delegate” |
| Permissions (delegate) | Valid JSON matching permission schema; at least one permission granted | “Please select at least one permission for this delegate” |
| Account deletion confirmation | Exact string “DELETE” | “Please type DELETE to confirm” |

| Scenario | HTTP Status | Error Code | User-Facing Message |
| --- | --- | --- | --- |
| Invalid credentials (email or password) | 401 | INVALID_CREDENTIALS | Invalid email or password |
| Invalid TOTP code | 401 | INVALID_MFA_CODE | Invalid verification code |
| Account locked (too many attempts) | 429 | ACCOUNT_LOCKED | Too many attempts. Please try again in [X] minutes. |
| Session expired | 401 | SESSION_EXPIRED | Your session has expired. Please log in again. |
| Insufficient permissions | 403 | FORBIDDEN | You don’t have permission to perform this action. |
| Subscription required | 402 | SUBSCRIPTION_REQUIRED | An active subscription is required. Please update your payment method. |
| Account suspended | 402 | ACCOUNT_SUSPENDED | Your account is suspended due to payment failure. Read-only access available. |
| Email already registered | 409 | EMAIL_EXISTS | An account with this email already exists. |
| Invitation expired | 410 | INVITATION_EXPIRED | This invitation has expired. Please ask for a new one. |
| Invitation already accepted | 409 | INVITATION_USED | This invitation has already been accepted. |
| Rate limited | 429 | RATE_LIMITED | Too many requests. Please try again shortly. |
| Validation error | 422 | VALIDATION_ERROR | Please check your input. [field-specific messages in detail] |
| Server error | 500 | INTERNAL_ERROR | Something went wrong. Please try again. If the problem persists, contact support. |

| Field | Type | Description |
| --- | --- | --- |
| user_id | UUID | Authenticated user’s ID |
| role | ENUM (physician | delegate | admin) | User’s role |
| email | STRING | User’s email (for display/notifications) |
| full_name | STRING | User’s display name |
| subscription_status | ENUM | Current subscription state |
| acting_as_physician_id | UUID | null | For delegates: which physician’s data they are currently accessing. NULL for physicians (they access their own). Set via X-Physician-ID header on delegate requests. |
| permissions | OBJECT | null | For delegates: the permission set for the current physician context. NULL for physicians (all permissions). Checked by authorize() middleware. |
| session_id | UUID | Current session ID (for audit logging) |
| ip_address | INET | Client IP (for audit logging) |

| Event | Payload | Consumer |
| --- | --- | --- |
| user.registered | { user_id, email, full_name } | Notification Service (welcome email), Onboarding (trigger flow) |
| user.email_verified | { user_id } | Onboarding (advance flow) |
| user.mfa_configured | { user_id } | Onboarding (advance flow) |
| user.login | { user_id, ip, user_agent } | Notification Service (optional security alert for new device) |
| user.account_locked | { user_id, lock_duration, reason } | Notification Service (security alert email) |
| delegate.invited | { physician_id, delegate_email, invitation_token } | Notification Service (invitation email) |
| delegate.accepted | { physician_id, delegate_user_id } | Notification Service (confirmation to physician) |
| delegate.removed | { physician_id, delegate_user_id } | Notification Service (notification to delegate) |
| delegate.batch_approved | { physician_id, delegate_id, batch_id, claims_count } | Notification Service (notification to physician), Claim Lifecycle (release batch) |
| subscription.status_changed | { user_id, old_status, new_status } | Notification Service (payment alerts), all domains (access gating) |
| account.deletion_requested | { user_id, deletion_date } | All domains (prepare for data deletion) |
| account.deletion_executed | { user_id } | All domains (confirm data purged) |

| Question | Options | Decision Criteria |
| --- | --- | --- |
| Session token format | JWT (stateless, self-contained) vs. opaque token (server-side lookup) | JWT reduces database lookups but complicates revocation. Opaque token is simpler for session management and revocation but requires a session store. Given mandatory session revocation (IAM-006, IAM-009), opaque tokens with a fast session store (Redis or DB) may be simpler. |
| Password hashing algorithm | bcrypt vs. Argon2id | Argon2id is technically superior (memory-hard, resists GPU attacks) but has less library maturity in some ecosystems. bcrypt is battle-tested and universally supported. Choose based on framework support. |
| CSRF protection approach | Double-submit cookie vs. synchroniser token pattern | Framework-dependent. Double-submit is simpler for SPA architectures. Synchroniser token is more traditional. SameSite=Strict cookies provide a strong baseline regardless. |
| Event bus for domain events | In-process event emitter vs. message queue (Redis Pub/Sub, NATS) | In-process is simpler for single-server MVP. Message queue adds resilience and supports future horizontal scaling. Decision depends on overall architecture. |
| Session store | PostgreSQL vs. Redis | Redis provides sub-millisecond session lookups. PostgreSQL is simpler (no additional infrastructure). At MVP scale (≤100 users), PostgreSQL is sufficient. Redis becomes valuable at scale. |

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 1.0 | February 12, 2026 | Ian Faulkner | Initial Identity & Access functional requirements |

