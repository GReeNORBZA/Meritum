import {
  createHash,
  createHmac,
  randomUUID,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  timingSafeEqual,
} from 'node:crypto';
import { hash as argon2Hash, verify as argon2Verify } from '@node-rs/argon2';
// @ts-expect-error otplib v13 restructured exports; authenticator exists at runtime via preset-default
import { authenticator } from 'otplib';
import { type Register } from '@meritum/shared/schemas/iam.schema.js';
import {
  AuditAction,
  AuditCategory,
  DefaultPermissions,
  Role,
  type Permission,
} from '@meritum/shared/constants/iam.constants.js';
import { BusinessRuleError } from '../../lib/errors.js';

// ---------------------------------------------------------------------------
// Argon2id parameters (from CLAUDE.md)
// ---------------------------------------------------------------------------

const ARGON2_OPTIONS = {
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

// ---------------------------------------------------------------------------
// Token utilities
// ---------------------------------------------------------------------------

const TOKEN_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours

/** SHA-256 hash a plaintext token. Stored in DB instead of the raw value. */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// TOTP configuration (otplib)
// ---------------------------------------------------------------------------

authenticator.options = {
  algorithm: 'sha1',
  digits: 6,
  step: 30,
};

const TOTP_ISSUER = 'Meritum';

// ---------------------------------------------------------------------------
// AES-256-GCM encryption for TOTP secret at rest
// ---------------------------------------------------------------------------

const AES_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // GCM standard: 96 bits
const AUTH_TAG_LENGTH = 16; // 128 bits

function getEncryptionKey(): Buffer {
  const keyHex = process.env.TOTP_ENCRYPTION_KEY;
  if (!keyHex) {
    throw new Error('TOTP_ENCRYPTION_KEY environment variable is not set');
  }
  return Buffer.from(keyHex, 'hex');
}

export function encryptTotpSecret(plaintext: string): string {
  const key = getEncryptionKey();
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(AES_ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  // Store as: iv:authTag:ciphertext (all hex)
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

export function decryptTotpSecret(stored: string): string {
  const key = getEncryptionKey();
  const [ivHex, authTagHex, encryptedHex] = stored.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const encrypted = Buffer.from(encryptedHex, 'hex');
  const decipher = createDecipheriv(AES_ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}

// ---------------------------------------------------------------------------
// Recovery code generation
// ---------------------------------------------------------------------------

const RECOVERY_CODE_COUNT = 10;
const RECOVERY_CODE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // No 0/O, 1/I confusion

/**
 * Generate a single 8-character alphanumeric recovery code.
 * Format: XXXX-XXXX for readability.
 */
function generateRecoveryCode(): string {
  const bytes = randomBytes(8);
  let code = '';
  for (let i = 0; i < 8; i++) {
    code += RECOVERY_CODE_CHARS[bytes[i] % RECOVERY_CODE_CHARS.length];
  }
  return `${code.slice(0, 4)}-${code.slice(4)}`;
}

/**
 * Generate 10 recovery codes and their Argon2id hashes.
 * Returns both plaintext (shown once to user) and hashes (stored in DB).
 */
async function generateRecoveryCodes(): Promise<{
  plaintextCodes: string[];
  codeHashes: string[];
}> {
  const plaintextCodes: string[] = [];
  const codeHashes: string[] = [];

  for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
    const code = generateRecoveryCode();
    plaintextCodes.push(code);
    // Hash each code with Argon2id (strip the dash for hashing)
    const normalized = code.replace(/-/g, '');
    const hashed = await argon2Hash(normalized, ARGON2_OPTIONS);
    codeHashes.push(hashed);
  }

  return { plaintextCodes, codeHashes };
}

// ---------------------------------------------------------------------------
// Dependency interfaces (injected by handler / test)
// ---------------------------------------------------------------------------

export interface UserRepo {
  createUser(data: {
    email: string;
    passwordHash: string;
    fullName: string;
    phone?: string | null;
  }): Promise<{ userId: string; email: string }>;

  findUserByEmail(email: string): Promise<{ userId: string; email: string } | undefined>;

  updateUser(
    userId: string,
    data: { emailVerified?: boolean },
  ): Promise<{ userId: string } | undefined>;
}

export interface VerificationTokenRepo {
  createVerificationToken(data: {
    userId: string;
    tokenHash: string;
    expiresAt: Date;
  }): Promise<{ tokenHash: string }>;

  findVerificationTokenByHash(
    tokenHash: string,
  ): Promise<
    | { userId: string; tokenHash: string; expiresAt: Date; used: boolean }
    | undefined
  >;

  markVerificationTokenUsed(tokenHash: string): Promise<void>;
}

export interface AuditRepo {
  appendAuditLog(entry: {
    userId?: string | null;
    action: string;
    category: string;
    resourceType?: string | null;
    resourceId?: string | null;
    detail?: Record<string, unknown> | null;
    ipAddress?: string | null;
    userAgent?: string | null;
  }): Promise<unknown>;
}

export interface EventEmitter {
  emit(event: string, payload: Record<string, unknown>): void;
}

export interface MfaUserRepo {
  findUserById(userId: string): Promise<{
    userId: string;
    email: string;
    totpSecretEncrypted: string | null;
    mfaConfigured: boolean;
  } | undefined>;

  setMfaSecret(userId: string, encryptedSecret: string): Promise<void>;
  setMfaConfigured(userId: string): Promise<void>;
}

export interface RecoveryCodeRepo {
  createRecoveryCodes(userId: string, codeHashes: string[]): Promise<unknown[]>;
}

export interface ServiceDeps {
  userRepo: UserRepo;
  verificationTokenRepo: VerificationTokenRepo;
  auditRepo: AuditRepo;
  events: EventEmitter;
}

export interface MfaServiceDeps {
  userRepo: MfaUserRepo;
  recoveryCodeRepo: RecoveryCodeRepo;
  auditRepo: AuditRepo;
  events: EventEmitter;
}

// ---------------------------------------------------------------------------
// Service: Registration
// ---------------------------------------------------------------------------

export interface RegisterResult {
  userId: string;
}

/**
 * Register a new physician user.
 *
 * Anti-enumeration: if the email already exists, we do NOT return an error.
 * Instead we emit a `USER_ALREADY_EXISTS` event (so the notification service
 * can send a "someone tried to register with your email" notice) and return
 * a synthetic userId (the existing user's ID). From the caller's perspective
 * the response is identical regardless of whether the email was new or not.
 */
export async function registerUser(
  deps: ServiceDeps,
  data: Register,
): Promise<RegisterResult> {
  const email = data.email.toLowerCase();
  const passwordHash = await argon2Hash(data.password, ARGON2_OPTIONS);

  // Attempt to create the user
  try {
    const user = await deps.userRepo.createUser({
      email,
      passwordHash,
      fullName: data.full_name,
      phone: data.phone ?? null,
    });

    // Generate email verification token
    const rawToken = randomUUID();
    const tokenHash = hashToken(rawToken);
    const expiresAt = new Date(Date.now() + TOKEN_EXPIRY_MS);

    await deps.verificationTokenRepo.createVerificationToken({
      userId: user.userId,
      tokenHash,
      expiresAt,
    });

    // Audit: auth.registered
    await deps.auditRepo.appendAuditLog({
      userId: user.userId,
      action: AuditAction.AUTH_REGISTERED,
      category: AuditCategory.AUTH,
      resourceType: 'user',
      resourceId: user.userId,
      detail: { email },
    });

    // Emit event for notification service (sends verification email)
    deps.events.emit('USER_REGISTERED', {
      userId: user.userId,
      email,
      verificationToken: rawToken,
    });

    return { userId: user.userId };
  } catch (err: unknown) {
    // Anti-enumeration: if email already exists, pretend success
    const isUniqueViolation =
      err instanceof Error &&
      'code' in err &&
      (err as { code: string }).code === '23505';

    if (isUniqueViolation) {
      // Look up the existing user to get their userId for the response
      const existing = await deps.userRepo.findUserByEmail(email);

      // Emit event so notification service can warn the existing user
      if (existing) {
        deps.events.emit('USER_ALREADY_EXISTS', {
          userId: existing.userId,
          email,
        });
      }

      // Return the existing userId — caller cannot distinguish from new user
      return { userId: existing?.userId ?? randomUUID() };
    }

    // Re-throw unexpected errors
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Service: Email Verification
// ---------------------------------------------------------------------------

export interface VerifyEmailResult {
  mfa_setup_required: boolean;
}

/**
 * Verify a user's email using the token sent during registration.
 *
 * Validates the token hash, checks expiry, marks email_verified = true,
 * and emits an audit event.
 */
export async function verifyEmail(
  deps: ServiceDeps,
  token: string,
): Promise<VerifyEmailResult> {
  const tokenHash = hashToken(token);

  const record =
    await deps.verificationTokenRepo.findVerificationTokenByHash(tokenHash);

  if (!record) {
    throw new BusinessRuleError('Invalid or expired verification token');
  }

  if (record.used) {
    throw new BusinessRuleError('Verification token has already been used');
  }

  if (record.expiresAt.getTime() < Date.now()) {
    throw new BusinessRuleError('Verification token has expired');
  }

  // Mark token as consumed
  await deps.verificationTokenRepo.markVerificationTokenUsed(tokenHash);

  // Set email_verified = true on the user
  await deps.userRepo.updateUser(record.userId, { emailVerified: true });

  // Audit: auth.email_verified
  await deps.auditRepo.appendAuditLog({
    userId: record.userId,
    action: AuditAction.AUTH_EMAIL_VERIFIED,
    category: AuditCategory.AUTH,
    resourceType: 'user',
    resourceId: record.userId,
  });

  return { mfa_setup_required: true };
}

// ---------------------------------------------------------------------------
// Service: MFA Setup
// ---------------------------------------------------------------------------

export interface InitiateMfaSetupResult {
  qr_code_uri: string;
  manual_key: string;
}

/**
 * Generate a TOTP secret, encrypt it with AES-256-GCM, and store it on the user.
 * Returns the QR code URI and manual key for the user to scan/enter in their
 * authenticator app. The secret is NOT active until confirmMfaSetup is called.
 */
export async function initiateMfaSetup(
  deps: MfaServiceDeps,
  userId: string,
): Promise<InitiateMfaSetupResult> {
  const user = await deps.userRepo.findUserById(userId);
  if (!user) {
    throw new BusinessRuleError('User not found');
  }

  // Generate TOTP secret
  const secret = authenticator.generateSecret();

  // Encrypt and store
  const encryptedSecret = encryptTotpSecret(secret);
  await deps.userRepo.setMfaSecret(userId, encryptedSecret);

  // Build otpauth:// URI for QR code
  const otpauthUri = authenticator.keyuri(user.email, TOTP_ISSUER, secret);

  return {
    qr_code_uri: otpauthUri,
    manual_key: secret,
  };
}

// ---------------------------------------------------------------------------
// Service: MFA Confirmation
// ---------------------------------------------------------------------------

export interface ConfirmMfaSetupResult {
  recovery_codes: string[];
}

/**
 * Verify a TOTP code against the stored (encrypted) secret.
 * If valid: set mfa_configured = true, generate 10 recovery codes,
 * hash each with Argon2id, store hashes, return plaintext codes.
 */
export async function confirmMfaSetup(
  deps: MfaServiceDeps,
  userId: string,
  totpCode: string,
): Promise<ConfirmMfaSetupResult> {
  const user = await deps.userRepo.findUserById(userId);
  if (!user) {
    throw new BusinessRuleError('User not found');
  }

  if (!user.totpSecretEncrypted) {
    throw new BusinessRuleError('MFA setup has not been initiated');
  }

  // Decrypt and verify TOTP code
  const secret = decryptTotpSecret(user.totpSecretEncrypted);
  const isValid = authenticator.verify({ token: totpCode, secret });

  if (!isValid) {
    throw new BusinessRuleError('Invalid TOTP code');
  }

  // Mark MFA as configured
  await deps.userRepo.setMfaConfigured(userId);

  // Generate recovery codes
  const { plaintextCodes, codeHashes } = await generateRecoveryCodes();
  await deps.recoveryCodeRepo.createRecoveryCodes(userId, codeHashes);

  // Audit: auth.mfa_setup
  await deps.auditRepo.appendAuditLog({
    userId,
    action: AuditAction.AUTH_MFA_SETUP,
    category: AuditCategory.AUTH,
    resourceType: 'user',
    resourceId: userId,
  });

  // Emit event
  deps.events.emit('MFA_SETUP_COMPLETE', { userId });

  return { recovery_codes: plaintextCodes };
}

// ---------------------------------------------------------------------------
// Service: Regenerate Recovery Codes
// ---------------------------------------------------------------------------

export interface RegenerateRecoveryCodesResult {
  recovery_codes: string[];
}

/**
 * Verify current TOTP first, then generate new 10 recovery codes,
 * replacing old ones. Returns plaintext codes (shown once).
 */
export async function regenerateRecoveryCodes(
  deps: MfaServiceDeps,
  userId: string,
  totpCode: string,
): Promise<RegenerateRecoveryCodesResult> {
  const user = await deps.userRepo.findUserById(userId);
  if (!user) {
    throw new BusinessRuleError('User not found');
  }

  if (!user.totpSecretEncrypted) {
    throw new BusinessRuleError('MFA is not configured');
  }

  // Verify current TOTP
  const secret = decryptTotpSecret(user.totpSecretEncrypted);
  const isValid = authenticator.verify({ token: totpCode, secret });

  if (!isValid) {
    throw new BusinessRuleError('Invalid TOTP code');
  }

  // Generate new recovery codes (old ones are deleted by the repository)
  const { plaintextCodes, codeHashes } = await generateRecoveryCodes();
  await deps.recoveryCodeRepo.createRecoveryCodes(userId, codeHashes);

  // Audit: account.recovery_codes_regenerated
  await deps.auditRepo.appendAuditLog({
    userId,
    action: AuditAction.ACCOUNT_RECOVERY_CODES_REGENERATED,
    category: AuditCategory.ACCOUNT,
    resourceType: 'user',
    resourceId: userId,
  });

  // Emit event
  deps.events.emit('RECOVERY_CODES_REGENERATED', { userId });

  return { recovery_codes: plaintextCodes };
}

// ---------------------------------------------------------------------------
// Service: Reconfigure MFA
// ---------------------------------------------------------------------------

export interface ReconfigureMfaResult {
  qr_code_uri: string;
  manual_key: string;
}

/**
 * Verify current TOTP code, then generate a new secret and QR.
 * Resets mfa_configured to false — user must call confirmMfaSetup again.
 */
export async function reconfigureMfa(
  deps: MfaServiceDeps,
  userId: string,
  currentTotpCode: string,
): Promise<ReconfigureMfaResult> {
  const user = await deps.userRepo.findUserById(userId);
  if (!user) {
    throw new BusinessRuleError('User not found');
  }

  if (!user.totpSecretEncrypted) {
    throw new BusinessRuleError('MFA is not configured');
  }

  // Verify current TOTP before allowing reconfiguration
  const currentSecret = decryptTotpSecret(user.totpSecretEncrypted);
  const isValid = authenticator.verify({
    token: currentTotpCode,
    secret: currentSecret,
  });

  if (!isValid) {
    throw new BusinessRuleError('Invalid TOTP code');
  }

  // Generate new TOTP secret
  const newSecret = authenticator.generateSecret();
  const encryptedSecret = encryptTotpSecret(newSecret);
  await deps.userRepo.setMfaSecret(userId, encryptedSecret);

  // Build otpauth:// URI for QR code
  const otpauthUri = authenticator.keyuri(user.email, TOTP_ISSUER, newSecret);

  // Audit: account.mfa_reconfigured
  await deps.auditRepo.appendAuditLog({
    userId,
    action: AuditAction.ACCOUNT_MFA_RECONFIGURED,
    category: AuditCategory.ACCOUNT,
    resourceType: 'user',
    resourceId: userId,
  });

  // Emit event
  deps.events.emit('MFA_RECONFIGURED', { userId });

  return {
    qr_code_uri: otpauthUri,
    manual_key: newSecret,
  };
}

// ---------------------------------------------------------------------------
// MFA Session Token (HMAC-signed, 5 minute expiry)
// ---------------------------------------------------------------------------

const MFA_SESSION_TOKEN_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes

function getSessionSecret(): string {
  const secret = process.env.SESSION_SECRET;
  if (!secret) {
    throw new Error('SESSION_SECRET environment variable is not set');
  }
  return secret;
}

/**
 * Create a short-lived MFA session token: base64url(payload) + '.' + base64url(hmac)
 * Payload: JSON { userId, exp } where exp is Unix timestamp in ms.
 */
export function createMfaSessionToken(userId: string): string {
  const payload = JSON.stringify({
    userId,
    exp: Date.now() + MFA_SESSION_TOKEN_EXPIRY_MS,
  });
  const payloadB64 = Buffer.from(payload).toString('base64url');
  const sig = createHmac('sha256', getSessionSecret())
    .update(payloadB64)
    .digest('base64url');
  return `${payloadB64}.${sig}`;
}

/**
 * Verify and decode an MFA session token. Returns the userId if valid,
 * or null if the token is invalid or expired.
 */
export function verifyMfaSessionToken(token: string): string | null {
  const parts = token.split('.');
  if (parts.length !== 2) return null;

  const [payloadB64, sig] = parts;

  const expectedSig = createHmac('sha256', getSessionSecret())
    .update(payloadB64)
    .digest('base64url');

  // Constant-time comparison to prevent timing attacks
  try {
    const sigBuf = Buffer.from(sig, 'base64url');
    const expectedBuf = Buffer.from(expectedSig, 'base64url');
    if (sigBuf.length !== expectedBuf.length) return null;
    if (!timingSafeEqual(sigBuf, expectedBuf)) return null;
  } catch {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
    if (!payload.userId || !payload.exp) return null;
    if (Date.now() > payload.exp) return null;
    return payload.userId;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Login Service Dependencies
// ---------------------------------------------------------------------------

export interface LoginUserRepo {
  findUserByEmail(email: string): Promise<{
    userId: string;
    email: string;
    passwordHash: string;
    mfaConfigured: boolean;
    totpSecretEncrypted: string | null;
    failedLoginCount: number;
    lockedUntil: Date | null;
    isActive: boolean;
  } | undefined>;

  findUserById(userId: string): Promise<{
    userId: string;
    email: string;
    passwordHash: string;
    mfaConfigured: boolean;
    totpSecretEncrypted: string | null;
    failedLoginCount: number;
    lockedUntil: Date | null;
    isActive: boolean;
  } | undefined>;

  incrementFailedLogin(userId: string): Promise<void>;
  resetFailedLogin(userId: string): Promise<void>;
}

export interface LoginSessionRepo {
  createSession(data: {
    userId: string;
    tokenHash: string;
    ipAddress: string;
    userAgent: string;
  }): Promise<{ sessionId: string }>;
}

export interface LoginRecoveryCodeRepo {
  findUnusedRecoveryCodes(userId: string): Promise<Array<{
    codeId: string;
    codeHash: string;
    used: boolean;
  }>>;
  markRecoveryCodeUsed(codeId: string): Promise<void>;
  countRemainingCodes(userId: string): Promise<number>;
}

export interface LoginServiceDeps {
  userRepo: LoginUserRepo;
  sessionRepo: LoginSessionRepo;
  recoveryCodeRepo: LoginRecoveryCodeRepo;
  auditRepo: AuditRepo;
  events: EventEmitter;
}

// ---------------------------------------------------------------------------
// Service: Login Step 1 — Password Verification
// ---------------------------------------------------------------------------

export interface LoginStep1Result {
  mfa_required: true;
  mfa_session_token: string;
}

/**
 * Authenticate a user with email and password.
 *
 * Anti-enumeration: returns the same generic error for wrong email and wrong
 * password. Performs a dummy Argon2id hash when the user is not found to
 * prevent timing-based user enumeration.
 */
export async function loginStep1(
  deps: LoginServiceDeps,
  email: string,
  password: string,
  ipAddress: string,
): Promise<LoginStep1Result> {
  const normalizedEmail = email.toLowerCase();
  const user = await deps.userRepo.findUserByEmail(normalizedEmail);

  if (!user) {
    // Anti-enumeration: hash a dummy password so timing is consistent
    await argon2Hash('dummy-password-for-timing', ARGON2_OPTIONS);
    throw new BusinessRuleError('Invalid credentials');
  }

  // Check account lockout
  if (user.lockedUntil && user.lockedUntil.getTime() > Date.now()) {
    await deps.auditRepo.appendAuditLog({
      userId: user.userId,
      action: AuditAction.AUTH_LOGIN_FAILED,
      category: AuditCategory.AUTH,
      resourceType: 'user',
      resourceId: user.userId,
      detail: { reason: 'account_locked' },
      ipAddress,
    });
    throw new BusinessRuleError('Account is temporarily locked. Please try again later.');
  }

  // Verify password
  const passwordValid = await argon2Verify(user.passwordHash, password);

  if (!passwordValid) {
    await deps.userRepo.incrementFailedLogin(user.userId);
    await deps.auditRepo.appendAuditLog({
      userId: user.userId,
      action: AuditAction.AUTH_LOGIN_FAILED,
      category: AuditCategory.AUTH,
      resourceType: 'user',
      resourceId: user.userId,
      detail: { reason: 'invalid_password' },
      ipAddress,
    });
    throw new BusinessRuleError('Invalid credentials');
  }

  // Check MFA is configured
  if (!user.mfaConfigured) {
    throw new BusinessRuleError('MFA setup required before login');
  }

  // Generate MFA session token
  const mfaSessionToken = createMfaSessionToken(user.userId);

  // Audit: auth.login_success (password step passed)
  await deps.auditRepo.appendAuditLog({
    userId: user.userId,
    action: AuditAction.AUTH_LOGIN_SUCCESS,
    category: AuditCategory.AUTH,
    resourceType: 'user',
    resourceId: user.userId,
    detail: { step: 'password_verified' },
    ipAddress,
  });

  deps.events.emit('AUTH_LOGIN_SUCCESS', {
    userId: user.userId,
    step: 'password_verified',
  });

  return {
    mfa_required: true,
    mfa_session_token: mfaSessionToken,
  };
}

// ---------------------------------------------------------------------------
// Service: Login Step 2 — TOTP MFA
// ---------------------------------------------------------------------------

export interface LoginStep2Result {
  session_token: string;
}

/**
 * Complete login by verifying a TOTP code.
 *
 * Validates the MFA session token, verifies the TOTP code, creates a
 * session, and returns a session token (plaintext, to be set as cookie).
 */
export async function loginStep2Mfa(
  deps: LoginServiceDeps,
  mfaSessionToken: string,
  totpCode: string,
  ipAddress: string,
  userAgent: string,
): Promise<LoginStep2Result> {
  const userId = verifyMfaSessionToken(mfaSessionToken);
  if (!userId) {
    throw new BusinessRuleError('Invalid or expired MFA session');
  }

  const user = await deps.userRepo.findUserById(userId);
  if (!user || !user.totpSecretEncrypted) {
    throw new BusinessRuleError('Invalid or expired MFA session');
  }

  // Verify TOTP code
  const secret = decryptTotpSecret(user.totpSecretEncrypted);
  const isValid = authenticator.verify({ token: totpCode, secret });

  if (!isValid) {
    await deps.userRepo.incrementFailedLogin(user.userId);
    await deps.auditRepo.appendAuditLog({
      userId: user.userId,
      action: AuditAction.AUTH_LOGIN_MFA_FAILED,
      category: AuditCategory.AUTH,
      resourceType: 'user',
      resourceId: user.userId,
      detail: { method: 'totp' },
      ipAddress,
    });
    throw new BusinessRuleError('Invalid TOTP code');
  }

  // Reset failed login count on successful authentication
  await deps.userRepo.resetFailedLogin(user.userId);

  // Create session: 32 random bytes, hex-encoded. Store SHA-256 hash.
  const rawToken = randomBytes(32).toString('hex');
  const tokenHash = hashToken(rawToken);

  await deps.sessionRepo.createSession({
    userId: user.userId,
    tokenHash,
    ipAddress,
    userAgent,
  });

  // Audit: auth.login_mfa_success
  await deps.auditRepo.appendAuditLog({
    userId: user.userId,
    action: AuditAction.AUTH_LOGIN_MFA_SUCCESS,
    category: AuditCategory.AUTH,
    resourceType: 'user',
    resourceId: user.userId,
    detail: { method: 'totp' },
    ipAddress,
    userAgent,
  });

  deps.events.emit('AUTH_LOGIN_MFA_SUCCESS', {
    userId: user.userId,
    method: 'totp',
  });

  return { session_token: rawToken };
}

// ---------------------------------------------------------------------------
// Service: Login Step 2 — Recovery Code
// ---------------------------------------------------------------------------

export interface LoginStep2RecoveryResult {
  session_token: string;
  remaining_codes: number;
}

/**
 * Complete login using a recovery code instead of TOTP.
 *
 * Loads all unused recovery code hashes for the user and verifies the
 * provided code against each using Argon2id. This is intentionally slow
 * for security.
 */
export async function loginStep2Recovery(
  deps: LoginServiceDeps,
  mfaSessionToken: string,
  recoveryCode: string,
  ipAddress: string,
  userAgent: string,
): Promise<LoginStep2RecoveryResult> {
  const userId = verifyMfaSessionToken(mfaSessionToken);
  if (!userId) {
    throw new BusinessRuleError('Invalid or expired MFA session');
  }

  const user = await deps.userRepo.findUserById(userId);
  if (!user) {
    throw new BusinessRuleError('Invalid or expired MFA session');
  }

  // Load all unused recovery codes
  const unusedCodes = await deps.recoveryCodeRepo.findUnusedRecoveryCodes(user.userId);

  // Normalize recovery code (strip dashes, uppercase)
  const normalized = recoveryCode.replace(/-/g, '').toUpperCase();

  // Try each hash with Argon2id (intentionally slow for security)
  let matchedCodeId: string | null = null;
  for (const code of unusedCodes) {
    try {
      const matches = await argon2Verify(code.codeHash, normalized);
      if (matches) {
        matchedCodeId = code.codeId;
        break;
      }
    } catch {
      // Argon2 verify can throw on malformed hashes; continue
    }
  }

  if (!matchedCodeId) {
    await deps.userRepo.incrementFailedLogin(user.userId);
    await deps.auditRepo.appendAuditLog({
      userId: user.userId,
      action: AuditAction.AUTH_LOGIN_MFA_FAILED,
      category: AuditCategory.AUTH,
      resourceType: 'user',
      resourceId: user.userId,
      detail: { method: 'recovery_code' },
      ipAddress,
    });
    throw new BusinessRuleError('Invalid recovery code');
  }

  // Mark the matched code as used
  await deps.recoveryCodeRepo.markRecoveryCodeUsed(matchedCodeId);

  // Reset failed login count
  await deps.userRepo.resetFailedLogin(user.userId);

  // Create session
  const rawToken = randomBytes(32).toString('hex');
  const tokenHash = hashToken(rawToken);

  await deps.sessionRepo.createSession({
    userId: user.userId,
    tokenHash,
    ipAddress,
    userAgent,
  });

  // Count remaining codes
  const remainingCodes = await deps.recoveryCodeRepo.countRemainingCodes(user.userId);

  // Audit: auth.login_recovery_used
  await deps.auditRepo.appendAuditLog({
    userId: user.userId,
    action: AuditAction.AUTH_LOGIN_RECOVERY_USED,
    category: AuditCategory.AUTH,
    resourceType: 'user',
    resourceId: user.userId,
    detail: { remaining_codes: remainingCodes },
    ipAddress,
    userAgent,
  });

  deps.events.emit('AUTH_LOGIN_RECOVERY_USED', {
    userId: user.userId,
    remainingCodes,
  });

  return {
    session_token: rawToken,
    remaining_codes: remainingCodes,
  };
}

// ---------------------------------------------------------------------------
// Session Management Dependencies
// ---------------------------------------------------------------------------

export interface SessionManagementSessionRepo {
  findSessionByTokenHash(tokenHash: string): Promise<{
    session: {
      sessionId: string;
      userId: string;
      tokenHash: string;
      ipAddress: string;
      userAgent: string;
      createdAt: Date;
      lastActiveAt: Date;
      revoked: boolean;
      revokedReason: string | null;
    };
    user: {
      userId: string;
      role: string;
      subscriptionStatus: string;
    };
  } | undefined>;
  refreshSession(sessionId: string): Promise<void>;
  listActiveSessions(userId: string): Promise<Array<{
    sessionId: string;
    userId: string;
    ipAddress: string;
    userAgent: string;
    createdAt: Date;
    lastActiveAt: Date;
    revoked: boolean;
    revokedReason: string | null;
  }>>;
  revokeSession(sessionId: string, reason: string): Promise<void>;
  revokeAllUserSessions(
    userId: string,
    exceptSessionId: string | undefined,
    reason: string,
  ): Promise<void>;
}

export interface SessionManagementDeps {
  sessionRepo: SessionManagementSessionRepo;
  auditRepo: AuditRepo;
  events: EventEmitter;
}

// ---------------------------------------------------------------------------
// Service: Validate Session
// ---------------------------------------------------------------------------

export interface AuthContext {
  userId: string;
  role: string;
  subscriptionStatus: string;
  sessionId: string;
  delegateContext?: {
    delegateUserId: string;
    physicianProviderId: string;
    permissions: string[];
    linkageId: string;
  };
}

/**
 * Validate a session by its token hash.
 *
 * Finds the session, checks both absolute expiry (24h) and idle expiry (60min).
 * On success, refreshes the idle timer and returns an AuthContext.
 * Returns null if the session is invalid, expired, or revoked.
 */
export async function validateSession(
  deps: SessionManagementDeps,
  tokenHash: string,
): Promise<AuthContext | null> {
  const result = await deps.sessionRepo.findSessionByTokenHash(tokenHash);
  if (!result) return null;

  // findSessionByTokenHash already checks expiry and revocation in the repository,
  // but we rely on the repository doing both absolute (24h) and idle (60min) checks.
  // If it returned a result, the session is valid.

  // Refresh idle timer
  await deps.sessionRepo.refreshSession(result.session.sessionId);

  const ctx: AuthContext = {
    userId: result.user.userId,
    role: result.user.role,
    subscriptionStatus: result.user.subscriptionStatus,
    sessionId: result.session.sessionId,
  };

  // Include delegate context if present (populated after physician context switch)
  if ((result.user as any).delegateContext) {
    ctx.delegateContext = (result.user as any).delegateContext;
  }

  return ctx;
}

// ---------------------------------------------------------------------------
// Service: List Sessions
// ---------------------------------------------------------------------------

export interface SessionInfo {
  sessionId: string;
  ipAddress: string;
  userAgent: string;
  createdAt: Date;
  lastActiveAt: Date;
}

/**
 * List all active sessions for a user.
 * Returns session metadata (id, ip, user_agent, created_at, last_active_at).
 */
export async function listSessions(
  deps: SessionManagementDeps,
  userId: string,
): Promise<SessionInfo[]> {
  const sessions = await deps.sessionRepo.listActiveSessions(userId);
  return sessions.map((s) => ({
    sessionId: s.sessionId,
    ipAddress: s.ipAddress,
    userAgent: s.userAgent,
    createdAt: s.createdAt,
    lastActiveAt: s.lastActiveAt,
  }));
}

// ---------------------------------------------------------------------------
// Service: Revoke Session
// ---------------------------------------------------------------------------

/**
 * Revoke a specific session. Verifies the session belongs to the requesting
 * userId — no cross-user session revocation.
 */
export async function revokeSession(
  deps: SessionManagementDeps,
  userId: string,
  sessionId: string,
): Promise<void> {
  // Verify the session belongs to this user
  const sessions = await deps.sessionRepo.listActiveSessions(userId);
  const session = sessions.find((s) => s.sessionId === sessionId);

  if (!session) {
    throw new BusinessRuleError('Session not found');
  }

  if (session.userId !== userId) {
    throw new BusinessRuleError('Session not found');
  }

  await deps.sessionRepo.revokeSession(sessionId, 'revoked_remote');

  await deps.auditRepo.appendAuditLog({
    userId,
    action: AuditAction.AUTH_SESSION_REVOKED,
    category: AuditCategory.AUTH,
    resourceType: 'session',
    resourceId: sessionId,
  });

  deps.events.emit('auth.session_revoked', { userId, sessionId });
}

// ---------------------------------------------------------------------------
// Service: Revoke All Sessions
// ---------------------------------------------------------------------------

/**
 * Revoke all sessions for a user except the current session.
 */
export async function revokeAllSessions(
  deps: SessionManagementDeps,
  userId: string,
  currentSessionId: string,
): Promise<void> {
  await deps.sessionRepo.revokeAllUserSessions(
    userId,
    currentSessionId,
    'revoked_remote',
  );

  await deps.auditRepo.appendAuditLog({
    userId,
    action: AuditAction.AUTH_SESSION_REVOKED_ALL,
    category: AuditCategory.AUTH,
    resourceType: 'session',
    resourceId: userId,
  });

  deps.events.emit('auth.session_revoked_all', { userId, currentSessionId });
}

// ---------------------------------------------------------------------------
// Service: Logout
// ---------------------------------------------------------------------------

/**
 * Revoke a session with reason 'logout'.
 */
export async function logout(
  deps: SessionManagementDeps,
  sessionId: string,
  userId: string,
): Promise<void> {
  await deps.sessionRepo.revokeSession(sessionId, 'logout');

  await deps.auditRepo.appendAuditLog({
    userId,
    action: AuditAction.AUTH_LOGOUT,
    category: AuditCategory.AUTH,
    resourceType: 'session',
    resourceId: sessionId,
  });

  deps.events.emit('auth.logout', { userId, sessionId });
}

// ---------------------------------------------------------------------------
// Password Reset Dependencies
// ---------------------------------------------------------------------------

export interface PasswordResetUserRepo {
  findUserByEmail(email: string): Promise<{
    userId: string;
    email: string;
  } | undefined>;
  setPasswordHash(userId: string, passwordHash: string): Promise<void>;
}

export interface PasswordResetTokenRepo {
  createPasswordResetToken(data: {
    userId: string;
    tokenHash: string;
    expiresAt: Date;
  }): Promise<{ tokenHash: string }>;

  findPasswordResetTokenByHash(tokenHash: string): Promise<{
    userId: string;
    tokenHash: string;
    expiresAt: Date;
    used: boolean;
  } | undefined>;

  markPasswordResetTokenUsed(tokenHash: string): Promise<void>;
}

export interface PasswordResetSessionRepo {
  revokeAllUserSessions(
    userId: string,
    exceptSessionId: string | undefined,
    reason: string,
  ): Promise<void>;
}

export interface PasswordResetDeps {
  userRepo: PasswordResetUserRepo;
  tokenRepo: PasswordResetTokenRepo;
  sessionRepo: PasswordResetSessionRepo;
  auditRepo: AuditRepo;
  events: EventEmitter;
}

// ---------------------------------------------------------------------------
// Service: Request Password Reset
// ---------------------------------------------------------------------------

const PASSWORD_RESET_TOKEN_EXPIRY_MS = 60 * 60 * 1000; // 1 hour

export interface RequestPasswordResetResult {
  success: true;
}

/**
 * Request a password reset. Always returns success (anti-enumeration).
 *
 * If the user exists: generates a reset token (UUID), stores its SHA-256
 * hash with 1-hour expiry, and emits USER_PASSWORD_RESET_REQUESTED event
 * for the notification service.
 *
 * If the user does not exist: performs a dummy hash to keep response timing
 * consistent, then returns the same success response.
 */
export async function requestPasswordReset(
  deps: PasswordResetDeps,
  email: string,
): Promise<RequestPasswordResetResult> {
  const normalizedEmail = email.toLowerCase();
  const user = await deps.userRepo.findUserByEmail(normalizedEmail);

  if (!user) {
    // Anti-enumeration: dummy hash to keep timing consistent
    await argon2Hash('dummy-password-for-timing', ARGON2_OPTIONS);
    return { success: true };
  }

  // Generate reset token
  const rawToken = randomUUID();
  const tokenHash = hashToken(rawToken);
  const expiresAt = new Date(Date.now() + PASSWORD_RESET_TOKEN_EXPIRY_MS);

  await deps.tokenRepo.createPasswordResetToken({
    userId: user.userId,
    tokenHash,
    expiresAt,
  });

  // Audit
  await deps.auditRepo.appendAuditLog({
    userId: user.userId,
    action: AuditAction.AUTH_PASSWORD_RESET_REQUESTED,
    category: AuditCategory.AUTH,
    resourceType: 'user',
    resourceId: user.userId,
    detail: { email: normalizedEmail },
  });

  // Emit event for notification service
  deps.events.emit('USER_PASSWORD_RESET_REQUESTED', {
    userId: user.userId,
    email: normalizedEmail,
    resetToken: rawToken,
  });

  return { success: true };
}

// ---------------------------------------------------------------------------
// Service: Reset Password
// ---------------------------------------------------------------------------

export interface ResetPasswordResult {
  success: true;
}

/**
 * Reset a user's password using a reset token.
 *
 * Verifies the token hash, checks expiry, hashes the new password with
 * Argon2id, updates the user, and invalidates ALL sessions (force re-login).
 */
export async function resetPassword(
  deps: PasswordResetDeps,
  token: string,
  newPassword: string,
): Promise<ResetPasswordResult> {
  const tokenHash = hashToken(token);

  const record = await deps.tokenRepo.findPasswordResetTokenByHash(tokenHash);

  if (!record) {
    throw new BusinessRuleError('Invalid or expired reset token');
  }

  if (record.used) {
    throw new BusinessRuleError('Reset token has already been used');
  }

  if (record.expiresAt.getTime() < Date.now()) {
    throw new BusinessRuleError('Reset token has expired');
  }

  // Mark token as consumed
  await deps.tokenRepo.markPasswordResetTokenUsed(tokenHash);

  // Hash new password
  const passwordHash = await argon2Hash(newPassword, ARGON2_OPTIONS);

  // Update user password
  await deps.userRepo.setPasswordHash(record.userId, passwordHash);

  // Invalidate ALL sessions (force re-login)
  await deps.sessionRepo.revokeAllUserSessions(
    record.userId,
    undefined,
    'password_reset',
  );

  // Audit
  await deps.auditRepo.appendAuditLog({
    userId: record.userId,
    action: AuditAction.AUTH_PASSWORD_RESET_COMPLETED,
    category: AuditCategory.AUTH,
    resourceType: 'user',
    resourceId: record.userId,
  });

  // Emit event
  deps.events.emit('auth.password_reset_completed', {
    userId: record.userId,
  });

  return { success: true };
}

// ---------------------------------------------------------------------------
// Delegate Management Dependencies
// ---------------------------------------------------------------------------

/** Permissions that CANNOT be granted to a delegate. */
const FORBIDDEN_DELEGATE_PERMISSIONS: readonly string[] = [
  'DELEGATE_MANAGE',
  'SUBSCRIPTION_MANAGE',
  'DATA_EXPORT',
];

/** Invitation token expires in 72 hours. */
const INVITATION_TOKEN_EXPIRY_MS = 72 * 60 * 60 * 1000;

export interface DelegateUserRepo {
  findUserByEmail(email: string): Promise<{
    userId: string;
    email: string;
    role: string;
  } | undefined>;

  findUserById(userId: string): Promise<{
    userId: string;
    email: string;
    role: string;
  } | undefined>;

  createUser(data: {
    email: string;
    passwordHash: string;
    fullName: string;
    role: string;
  }): Promise<{ userId: string; email: string }>;
}

export interface DelegateInvitationRepo {
  createInvitation(data: {
    physicianUserId: string;
    delegateEmail: string;
    tokenHash: string;
    permissions: string[];
    expiresAt: Date;
  }): Promise<{ invitationId: string }>;

  findInvitationByTokenHash(tokenHash: string): Promise<{
    invitationId: string;
    physicianUserId: string;
    delegateEmail: string;
    tokenHash: string;
    permissions: string[];
    expiresAt: Date;
    accepted: boolean;
  } | undefined>;

  markInvitationAccepted(invitationId: string): Promise<void>;
}

export interface DelegateLinkageRepo {
  createDelegateLinkage(data: {
    physicianUserId: string;
    delegateUserId: string;
    permissions: string[];
    canApproveBatches: boolean;
  }): Promise<{ linkageId: string; physicianUserId: string; delegateUserId: string; permissions: string[]; canApproveBatches: boolean; isActive: boolean }>;

  findLinkage(
    physicianUserId: string,
    delegateUserId: string,
  ): Promise<{
    linkageId: string;
    physicianUserId: string;
    delegateUserId: string;
    permissions: string[];
    canApproveBatches: boolean;
    isActive: boolean;
  } | undefined>;

  findLinkageById(linkageId: string): Promise<{
    linkageId: string;
    physicianUserId: string;
    delegateUserId: string;
    permissions: string[];
    canApproveBatches: boolean;
    isActive: boolean;
  } | undefined>;

  listDelegatesForPhysician(physicianUserId: string): Promise<Array<{
    linkage: {
      linkageId: string;
      physicianUserId: string;
      delegateUserId: string;
      permissions: string[];
      canApproveBatches: boolean;
      isActive: boolean;
    };
    user: { userId: string; fullName: string; email: string };
    lastLogin: Date | null;
  }>>;

  listPhysiciansForDelegate(delegateUserId: string): Promise<Array<{
    linkage: {
      linkageId: string;
      physicianUserId: string;
      delegateUserId: string;
      permissions: string[];
      canApproveBatches: boolean;
      isActive: boolean;
    };
    physician: { userId: string; fullName: string; email: string };
  }>>;

  updateLinkagePermissions(
    linkageId: string,
    permissions: string[],
    canApproveBatches: boolean,
  ): Promise<{ linkageId: string } | undefined>;

  deactivateLinkage(linkageId: string): Promise<{ linkageId: string } | undefined>;
}

export interface DelegateSessionRepo {
  revokeAllUserSessions(
    userId: string,
    exceptSessionId: string | undefined,
    reason: string,
  ): Promise<void>;
}

export interface DelegateServiceDeps {
  userRepo: DelegateUserRepo;
  invitationRepo: DelegateInvitationRepo;
  linkageRepo: DelegateLinkageRepo;
  sessionRepo: DelegateSessionRepo;
  auditRepo: AuditRepo;
  events: EventEmitter;
}

// ---------------------------------------------------------------------------
// Service: Invite Delegate
// ---------------------------------------------------------------------------

export interface InviteDelegateResult {
  invitationId: string;
  token: string;
}

/**
 * Validate requested permissions and create a delegate invitation.
 *
 * Security: Delegates cannot be granted DELEGATE_MANAGE, SUBSCRIPTION_MANAGE,
 * or DATA_EXPORT permissions. The invitation token is hashed before storage;
 * the plaintext token is returned for inclusion in the notification email.
 */
export async function inviteDelegate(
  deps: DelegateServiceDeps,
  physicianUserId: string,
  email: string,
  permissions: string[],
): Promise<InviteDelegateResult> {
  // Validate permissions: must be a subset of allowed delegate permissions
  const allowedPermissions = DefaultPermissions[Role.DELEGATE] as readonly string[];

  for (const perm of permissions) {
    if (FORBIDDEN_DELEGATE_PERMISSIONS.includes(perm)) {
      throw new BusinessRuleError(
        `Permission '${perm}' cannot be granted to delegates`,
      );
    }
    if (!allowedPermissions.includes(perm)) {
      throw new BusinessRuleError(
        `Invalid delegate permission: '${perm}'`,
      );
    }
  }

  // Generate invitation token
  const rawToken = randomUUID();
  const tokenHash = hashToken(rawToken);
  const expiresAt = new Date(Date.now() + INVITATION_TOKEN_EXPIRY_MS);
  const normalizedEmail = email.toLowerCase();

  const invitation = await deps.invitationRepo.createInvitation({
    physicianUserId,
    delegateEmail: normalizedEmail,
    tokenHash,
    permissions,
    expiresAt,
  });

  // Audit
  await deps.auditRepo.appendAuditLog({
    userId: physicianUserId,
    action: AuditAction.DELEGATE_INVITED,
    category: AuditCategory.DELEGATE,
    resourceType: 'invitation',
    resourceId: invitation.invitationId,
    detail: { delegateEmail: normalizedEmail, permissions },
  });

  // Emit event for notification service
  deps.events.emit('DELEGATE_INVITED', {
    physicianUserId,
    delegateEmail: normalizedEmail,
    invitationToken: rawToken,
    permissions,
  });

  return {
    invitationId: invitation.invitationId,
    token: rawToken,
  };
}

// ---------------------------------------------------------------------------
// Service: Accept Invitation
// ---------------------------------------------------------------------------

export interface AcceptInvitationResult {
  linkageId: string;
}

/**
 * Accept a delegate invitation. If the delegate's email matches an existing user,
 * create the linkage directly. If new, create user account + linkage.
 *
 * Security: Token is hashed and compared. Expired/already-accepted tokens are rejected.
 */
export async function acceptInvitation(
  deps: DelegateServiceDeps,
  token: string,
  registrationData?: { fullName: string; password: string },
): Promise<AcceptInvitationResult> {
  const tokenHash = hashToken(token);

  const invitation = await deps.invitationRepo.findInvitationByTokenHash(tokenHash);

  if (!invitation) {
    throw new BusinessRuleError('Invalid or expired invitation token');
  }

  if (invitation.accepted) {
    throw new BusinessRuleError('Invitation has already been accepted');
  }

  if (invitation.expiresAt.getTime() < Date.now()) {
    throw new BusinessRuleError('Invitation has expired');
  }

  // Determine delegate user
  let delegateUserId: string;
  const existingUser = await deps.userRepo.findUserByEmail(invitation.delegateEmail);

  if (existingUser) {
    delegateUserId = existingUser.userId;
  } else {
    // New user: registration data is required
    if (!registrationData?.fullName || !registrationData?.password) {
      throw new BusinessRuleError(
        'Registration data (fullName, password) is required for new delegate accounts',
      );
    }

    const passwordHash = await argon2Hash(registrationData.password, ARGON2_OPTIONS);
    const newUser = await deps.userRepo.createUser({
      email: invitation.delegateEmail,
      passwordHash,
      fullName: registrationData.fullName,
      role: Role.DELEGATE,
    });
    delegateUserId = newUser.userId;
  }

  // Mark invitation accepted
  await deps.invitationRepo.markInvitationAccepted(invitation.invitationId);

  // Create delegate linkage
  const linkage = await deps.linkageRepo.createDelegateLinkage({
    physicianUserId: invitation.physicianUserId,
    delegateUserId,
    permissions: invitation.permissions as string[],
    canApproveBatches: false,
  });

  // Audit
  await deps.auditRepo.appendAuditLog({
    userId: delegateUserId,
    action: AuditAction.DELEGATE_ACCEPTED,
    category: AuditCategory.DELEGATE,
    resourceType: 'delegate_linkage',
    resourceId: linkage.linkageId,
    detail: {
      physicianUserId: invitation.physicianUserId,
      permissions: invitation.permissions,
    },
  });

  // Emit event
  deps.events.emit('DELEGATE_ACCEPTED', {
    physicianUserId: invitation.physicianUserId,
    delegateUserId,
    linkageId: linkage.linkageId,
  });

  return { linkageId: linkage.linkageId };
}

// ---------------------------------------------------------------------------
// Service: List Delegates
// ---------------------------------------------------------------------------

export interface DelegateInfo {
  linkageId: string;
  delegateUserId: string;
  fullName: string;
  email: string;
  permissions: string[];
  canApproveBatches: boolean;
  lastLogin: Date | null;
  isActive: boolean;
}

/**
 * List all delegates for a physician with their permissions, last login, and active status.
 */
export async function listDelegates(
  deps: DelegateServiceDeps,
  physicianUserId: string,
): Promise<DelegateInfo[]> {
  const delegates = await deps.linkageRepo.listDelegatesForPhysician(physicianUserId);

  return delegates.map((d) => ({
    linkageId: d.linkage.linkageId,
    delegateUserId: d.linkage.delegateUserId,
    fullName: d.user.fullName,
    email: d.user.email,
    permissions: d.linkage.permissions as string[],
    canApproveBatches: d.linkage.canApproveBatches,
    lastLogin: d.lastLogin,
    isActive: d.linkage.isActive,
  }));
}

// ---------------------------------------------------------------------------
// Service: Update Delegate Permissions
// ---------------------------------------------------------------------------

export interface UpdateDelegatePermissionsResult {
  linkageId: string;
}

/**
 * Update a delegate's permissions. Validates that:
 * 1. The linkage belongs to the requesting physician
 * 2. The new permissions are within the allowed set
 */
export async function updateDelegatePermissions(
  deps: DelegateServiceDeps,
  physicianUserId: string,
  linkageId: string,
  permissions: string[],
  canApproveBatches: boolean,
): Promise<UpdateDelegatePermissionsResult> {
  // Validate permissions
  const allowedPermissions = DefaultPermissions[Role.DELEGATE] as readonly string[];

  for (const perm of permissions) {
    if (FORBIDDEN_DELEGATE_PERMISSIONS.includes(perm)) {
      throw new BusinessRuleError(
        `Permission '${perm}' cannot be granted to delegates`,
      );
    }
    if (!allowedPermissions.includes(perm)) {
      throw new BusinessRuleError(
        `Invalid delegate permission: '${perm}'`,
      );
    }
  }

  // Verify linkage belongs to this physician
  const linkage = await deps.linkageRepo.findLinkageById(linkageId);

  if (!linkage || linkage.physicianUserId !== physicianUserId) {
    throw new BusinessRuleError('Delegate linkage not found');
  }

  if (!linkage.isActive) {
    throw new BusinessRuleError('Delegate linkage is not active');
  }

  const updated = await deps.linkageRepo.updateLinkagePermissions(
    linkageId,
    permissions,
    canApproveBatches,
  );

  if (!updated) {
    throw new BusinessRuleError('Delegate linkage not found');
  }

  // Audit
  await deps.auditRepo.appendAuditLog({
    userId: physicianUserId,
    action: AuditAction.DELEGATE_PERMISSIONS_UPDATED,
    category: AuditCategory.DELEGATE,
    resourceType: 'delegate_linkage',
    resourceId: linkageId,
    detail: { permissions, canApproveBatches },
  });

  // Emit event
  deps.events.emit('DELEGATE_PERMISSIONS_UPDATED', {
    physicianUserId,
    linkageId,
    permissions,
    canApproveBatches,
  });

  return { linkageId };
}

// ---------------------------------------------------------------------------
// Service: Revoke Delegate
// ---------------------------------------------------------------------------

/**
 * Deactivate a delegate linkage and immediately revoke all of the delegate's
 * sessions for this physician context.
 *
 * Security: Revoking must be immediate — the delegate should not be able to
 * perform any further actions under this physician's account.
 */
export async function revokeDelegate(
  deps: DelegateServiceDeps,
  physicianUserId: string,
  linkageId: string,
): Promise<void> {
  // Verify linkage belongs to this physician
  const linkage = await deps.linkageRepo.findLinkageById(linkageId);

  if (!linkage || linkage.physicianUserId !== physicianUserId) {
    throw new BusinessRuleError('Delegate linkage not found');
  }

  // Deactivate the linkage
  await deps.linkageRepo.deactivateLinkage(linkageId);

  // Revoke all sessions for the delegate user
  await deps.sessionRepo.revokeAllUserSessions(
    linkage.delegateUserId,
    undefined,
    'revoked_remote',
  );

  // Audit
  await deps.auditRepo.appendAuditLog({
    userId: physicianUserId,
    action: AuditAction.DELEGATE_REVOKED,
    category: AuditCategory.DELEGATE,
    resourceType: 'delegate_linkage',
    resourceId: linkageId,
    detail: { delegateUserId: linkage.delegateUserId },
  });

  // Emit event
  deps.events.emit('DELEGATE_REVOKED', {
    physicianUserId,
    delegateUserId: linkage.delegateUserId,
    linkageId,
  });
}

// ---------------------------------------------------------------------------
// Service: List Physicians For Delegate
// ---------------------------------------------------------------------------

export interface PhysicianInfo {
  linkageId: string;
  physicianUserId: string;
  fullName: string;
  email: string;
  permissions: string[];
  canApproveBatches: boolean;
}

/**
 * Return all physician contexts a delegate has access to, with permissions per physician.
 */
export async function listPhysiciansForDelegate(
  deps: DelegateServiceDeps,
  delegateUserId: string,
): Promise<PhysicianInfo[]> {
  const physicians = await deps.linkageRepo.listPhysiciansForDelegate(delegateUserId);

  return physicians.map((p) => ({
    linkageId: p.linkage.linkageId,
    physicianUserId: p.linkage.physicianUserId,
    fullName: p.physician.fullName,
    email: p.physician.email,
    permissions: p.linkage.permissions as string[],
    canApproveBatches: p.linkage.canApproveBatches,
  }));
}

// ---------------------------------------------------------------------------
// Service: Switch Physician Context
// ---------------------------------------------------------------------------

export interface DelegateAuthContext {
  userId: string;
  role: 'delegate';
  delegateContext: {
    delegateUserId: string;
    physicianUserId: string;
    permissions: string[];
    canApproveBatches: boolean;
  };
}

/**
 * Verify that a delegate has an active linkage with the specified physician
 * and return an AuthContext populated with the delegate context.
 *
 * Security: This is the gate that prevents a delegate from accessing a
 * physician's data without an active linkage.
 */
export async function switchPhysicianContext(
  deps: DelegateServiceDeps,
  delegateUserId: string,
  physicianUserId: string,
): Promise<DelegateAuthContext> {
  const linkage = await deps.linkageRepo.findLinkage(
    physicianUserId,
    delegateUserId,
  );

  if (!linkage || !linkage.isActive) {
    throw new BusinessRuleError('No active linkage with this physician');
  }

  // Audit
  await deps.auditRepo.appendAuditLog({
    userId: delegateUserId,
    action: AuditAction.DELEGATE_CONTEXT_SWITCHED,
    category: AuditCategory.DELEGATE,
    resourceType: 'delegate_linkage',
    resourceId: linkage.linkageId,
    detail: { physicianUserId },
  });

  // Emit event
  deps.events.emit('DELEGATE_CONTEXT_SWITCHED', {
    delegateUserId,
    physicianUserId,
    linkageId: linkage.linkageId,
  });

  return {
    userId: delegateUserId,
    role: 'delegate',
    delegateContext: {
      delegateUserId,
      physicianUserId,
      permissions: linkage.permissions as string[],
      canApproveBatches: linkage.canApproveBatches,
    },
  };
}

// ---------------------------------------------------------------------------
// Account Management Dependencies
// ---------------------------------------------------------------------------

export interface AccountUserRepo {
  findUserById(userId: string): Promise<{
    userId: string;
    email: string;
    fullName: string;
    phone: string | null;
    role: string;
    subscriptionStatus: string;
    mfaConfigured: boolean;
    passwordHash: string;
    totpSecretEncrypted: string | null;
    isActive: boolean;
  } | undefined>;

  updateUser(
    userId: string,
    data: { fullName?: string; phone?: string | null },
  ): Promise<{ userId: string } | undefined>;

  deactivateUser(userId: string): Promise<void>;
}

export interface AccountSessionRepo {
  revokeAllUserSessions(
    userId: string,
    exceptSessionId: string | undefined,
    reason: string,
  ): Promise<void>;
}

export interface AccountDelegateLinkageRepo {
  listDelegatesForPhysician(physicianUserId: string): Promise<Array<{
    linkage: {
      linkageId: string;
      delegateUserId: string;
      isActive: boolean;
    };
    user: { userId: string; fullName: string; email: string };
    lastLogin: Date | null;
  }>>;

  deactivateLinkage(linkageId: string): Promise<{ linkageId: string } | undefined>;
}

export interface AccountServiceDeps {
  userRepo: AccountUserRepo;
  sessionRepo: AccountSessionRepo;
  linkageRepo: AccountDelegateLinkageRepo;
  auditRepo: AuditRepo;
  events: EventEmitter;
}

// ---------------------------------------------------------------------------
// Service: Get Account
// ---------------------------------------------------------------------------

export interface AccountInfo {
  userId: string;
  email: string;
  fullName: string;
  phone: string | null;
  role: string;
  subscriptionStatus: string;
  mfaConfigured: boolean;
}

/**
 * Return account info for the authenticated user.
 * Excludes sensitive fields (passwordHash, totpSecretEncrypted).
 */
export async function getAccount(
  deps: AccountServiceDeps,
  userId: string,
): Promise<AccountInfo> {
  const user = await deps.userRepo.findUserById(userId);
  if (!user || !user.isActive) {
    throw new BusinessRuleError('Account not found');
  }

  return {
    userId: user.userId,
    email: user.email,
    fullName: user.fullName,
    phone: user.phone,
    role: user.role,
    subscriptionStatus: user.subscriptionStatus,
    mfaConfigured: user.mfaConfigured,
  };
}

// ---------------------------------------------------------------------------
// Service: Update Account
// ---------------------------------------------------------------------------

export interface AccountUpdateResult {
  userId: string;
}

/**
 * Update name and/or phone. Email and password changes are not
 * supported via this endpoint (email requires re-verification,
 * password has its own reset flow).
 */
export async function updateAccount(
  deps: AccountServiceDeps,
  userId: string,
  data: { full_name?: string; phone?: string },
): Promise<AccountUpdateResult> {
  const user = await deps.userRepo.findUserById(userId);
  if (!user || !user.isActive) {
    throw new BusinessRuleError('Account not found');
  }

  const updatePayload: { fullName?: string; phone?: string | null } = {};
  if (data.full_name !== undefined) {
    updatePayload.fullName = data.full_name;
  }
  if (data.phone !== undefined) {
    updatePayload.phone = data.phone || null;
  }

  await deps.userRepo.updateUser(userId, updatePayload);

  // Audit: account.updated
  await deps.auditRepo.appendAuditLog({
    userId,
    action: AuditAction.ACCOUNT_UPDATED,
    category: AuditCategory.ACCOUNT,
    resourceType: 'user',
    resourceId: userId,
    detail: {
      fields: Object.keys(updatePayload),
    },
  });

  deps.events.emit('ACCOUNT_UPDATED', { userId });

  return { userId };
}

// ---------------------------------------------------------------------------
// Service: Request Account Deletion
// ---------------------------------------------------------------------------

export interface AccountDeletionResult {
  scheduledDeletionDate: string;
}

/** Grace period before permanent data deletion: 30 days. */
const DELETION_GRACE_PERIOD_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Request account deletion. Requires three-factor confirmation:
 * 1. Correct password (Argon2id)
 * 2. Valid TOTP code
 * 3. Typed confirmation === 'DELETE'
 *
 * On success: cancel Stripe subscription, invalidate all sessions,
 * deactivate all delegate linkages (notify delegates), schedule data
 * deletion in 30 days.
 */
export async function requestAccountDeletion(
  deps: AccountServiceDeps,
  userId: string,
  password: string,
  totpCode: string,
  confirmation: string,
): Promise<AccountDeletionResult> {
  // Factor 3: Typed confirmation
  if (confirmation !== 'DELETE') {
    throw new BusinessRuleError('Confirmation must be exactly "DELETE"');
  }

  const user = await deps.userRepo.findUserById(userId);
  if (!user || !user.isActive) {
    throw new BusinessRuleError('Account not found');
  }

  // Factor 1: Password verification
  const passwordValid = await argon2Verify(user.passwordHash, password);
  if (!passwordValid) {
    throw new BusinessRuleError('Invalid password');
  }

  // Factor 2: TOTP verification
  if (!user.totpSecretEncrypted) {
    throw new BusinessRuleError('MFA is not configured');
  }

  const secret = decryptTotpSecret(user.totpSecretEncrypted);
  const totpValid = authenticator.verify({ token: totpCode, secret });
  if (!totpValid) {
    throw new BusinessRuleError('Invalid TOTP code');
  }

  // Cancel Stripe subscription (emit event for platform domain to handle synchronously)
  deps.events.emit('SUBSCRIPTION_CANCEL_REQUESTED', { userId });

  // Invalidate all sessions
  await deps.sessionRepo.revokeAllUserSessions(userId, undefined, 'account_deleted');

  // Deactivate all delegate linkages
  const delegates = await deps.linkageRepo.listDelegatesForPhysician(userId);
  for (const delegate of delegates) {
    if (delegate.linkage.isActive) {
      await deps.linkageRepo.deactivateLinkage(delegate.linkage.linkageId);

      // Notify each delegate
      deps.events.emit('DELEGATE_ACCESS_REVOKED_ACCOUNT_DELETION', {
        delegateUserId: delegate.linkage.delegateUserId,
        physicianUserId: userId,
      });
    }
  }

  // Schedule data deletion in 30 days
  const scheduledDeletionDate = new Date(Date.now() + DELETION_GRACE_PERIOD_MS);

  // Deactivate the user account (soft delete)
  await deps.userRepo.deactivateUser(userId);

  // Audit: account.deletion_requested
  await deps.auditRepo.appendAuditLog({
    userId,
    action: AuditAction.ACCOUNT_DELETION_REQUESTED,
    category: AuditCategory.ACCOUNT,
    resourceType: 'user',
    resourceId: userId,
    detail: {
      scheduledDeletionDate: scheduledDeletionDate.toISOString(),
      delegatesDeactivated: delegates.filter((d) => d.linkage.isActive).length,
    },
  });

  // Emit account deletion event
  deps.events.emit('ACCOUNT_DELETION_REQUESTED', {
    userId,
    scheduledDeletionDate: scheduledDeletionDate.toISOString(),
  });

  return {
    scheduledDeletionDate: scheduledDeletionDate.toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Service: Check Subscription Access
// ---------------------------------------------------------------------------

export type AccessLevel = 'full' | 'read_only' | 'suspended';

export interface SubscriptionAccessResult {
  subscriptionStatus: string;
  accessLevel: AccessLevel;
}

/**
 * Return the user's subscription status and derived access level.
 * Used by auth middleware to gate features based on subscription state.
 *
 * - TRIAL / ACTIVE → full access
 * - PAST_DUE → read_only (can view but not create/submit)
 * - SUSPENDED / CANCELLED → suspended (no access except account management)
 */
export async function checkSubscriptionAccess(
  deps: AccountServiceDeps,
  userId: string,
): Promise<SubscriptionAccessResult> {
  const user = await deps.userRepo.findUserById(userId);
  if (!user || !user.isActive) {
    throw new BusinessRuleError('Account not found');
  }

  let accessLevel: AccessLevel;
  switch (user.subscriptionStatus) {
    case 'TRIAL':
    case 'ACTIVE':
      accessLevel = 'full';
      break;
    case 'PAST_DUE':
      accessLevel = 'read_only';
      break;
    case 'SUSPENDED':
    case 'CANCELLED':
    default:
      accessLevel = 'suspended';
      break;
  }

  return {
    subscriptionStatus: user.subscriptionStatus,
    accessLevel,
  };
}

// ---------------------------------------------------------------------------
// Audit Log Query Dependencies
// ---------------------------------------------------------------------------

export interface AuditLogQueryRepo {
  queryAuditLog(
    userId: string,
    filters?: {
      action?: string;
      category?: string;
      startDate?: string;
      endDate?: string;
      page?: number;
      pageSize?: number;
    },
  ): Promise<{
    data: Array<{
      logId: string;
      userId: string | null;
      action: string;
      category: string;
      resourceType: string | null;
      resourceId: string | null;
      detail: Record<string, unknown> | null;
      ipAddress: string | null;
      userAgent: string | null;
      createdAt: Date;
    }>;
    total: number;
  }>;
}

export interface AuditLogServiceDeps {
  auditLogRepo: AuditLogQueryRepo;
  auditRepo: AuditRepo;
}

// ---------------------------------------------------------------------------
// Service: Query Audit Log
// ---------------------------------------------------------------------------

export interface AuditLogQueryResult {
  data: Array<{
    logId: string;
    action: string;
    category: string;
    resourceType: string | null;
    resourceId: string | null;
    detail: Record<string, unknown> | null;
    ipAddress: string | null;
    createdAt: Date;
  }>;
  pagination: {
    total: number;
    page: number;
    pageSize: number;
    hasMore: boolean;
  };
}

/**
 * Query the audit log for the authenticated user with optional filters.
 * Scoped to the requesting user — a physician can only see their own audit trail.
 */
export async function queryAuditLog(
  deps: AuditLogServiceDeps,
  userId: string,
  filters: {
    action?: string;
    category?: string;
    startDate?: string;
    endDate?: string;
    page?: number;
    pageSize?: number;
  } = {},
): Promise<AuditLogQueryResult> {
  const page = filters.page ?? 1;
  const pageSize = Math.min(filters.pageSize ?? 50, 200);

  const result = await deps.auditLogRepo.queryAuditLog(userId, {
    action: filters.action,
    category: filters.category,
    startDate: filters.startDate,
    endDate: filters.endDate,
    page,
    pageSize,
  });

  // Audit the query itself
  await deps.auditRepo.appendAuditLog({
    userId,
    action: AuditAction.AUDIT_QUERIED,
    category: AuditCategory.AUDIT,
    resourceType: 'audit_log',
    detail: { filters },
  });

  return {
    data: result.data.map((entry) => ({
      logId: entry.logId,
      action: entry.action,
      category: entry.category,
      resourceType: entry.resourceType,
      resourceId: entry.resourceId,
      detail: entry.detail,
      ipAddress: entry.ipAddress,
      createdAt: entry.createdAt,
    })),
    pagination: {
      total: result.total,
      page,
      pageSize,
      hasMore: page * pageSize < result.total,
    },
  };
}
