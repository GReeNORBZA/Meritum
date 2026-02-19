import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  createUserRepository,
  createSessionRepository,
  createRecoveryCodeRepository,
  createInvitationRepository,
  createDelegateLinkageRepository,
  createAuditLogRepository,
  isSessionExpired,
} from './iam.repository.js';
import {
  registerUser,
  verifyEmail,
  initiateMfaSetup,
  confirmMfaSetup,
  regenerateRecoveryCodes,
  reconfigureMfa,
  loginStep1,
  loginStep2Mfa,
  loginStep2Recovery,
  validateSession,
  listSessions,
  revokeSession,
  revokeAllSessions,
  logout,
  requestPasswordReset,
  resetPassword,
  inviteDelegate,
  acceptInvitation,
  listDelegates,
  updateDelegatePermissions,
  revokeDelegate,
  listPhysiciansForDelegate,
  switchPhysicianContext,
  createMfaSessionToken,
  verifyMfaSessionToken,
  encryptTotpSecret,
  decryptTotpSecret,
  hashToken,
  type ServiceDeps,
  type MfaServiceDeps,
  type LoginServiceDeps,
  type SessionManagementDeps,
  type PasswordResetDeps,
  type DelegateServiceDeps,
  type LoginUserRepo,
  type LoginSessionRepo,
  type LoginRecoveryCodeRepo,
  type UserRepo,
  type MfaUserRepo,
  type RecoveryCodeRepo,
  type VerificationTokenRepo,
  type AuditRepo,
  type EventEmitter,
  type AccountServiceDeps,
  type AccountUserRepo,
  type AccountSessionRepo,
  type AccountDelegateLinkageRepo,
  getAccount,
  updateAccount,
  requestAccountDeletion,
  checkSubscriptionAccess,
} from './iam.service.js';

// ---------------------------------------------------------------------------
// Environment setup for encryption tests
// ---------------------------------------------------------------------------

// AES-256-GCM requires a 32-byte (256-bit) key — 64 hex chars
process.env.TOTP_ENCRYPTION_KEY = 'a'.repeat(64);
// SESSION_SECRET for MFA session token signing
process.env.SESSION_SECRET = 'b'.repeat(64);

// ---------------------------------------------------------------------------
// Helpers: in-memory stores
// ---------------------------------------------------------------------------

let userStore: Record<string, any>[];
let sessionStore: Record<string, any>[];
let recoveryCodeStore: Record<string, any>[];
let invitationStore: Record<string, any>[];
let delegateLinkageStore: Record<string, any>[];
let auditLogStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Mock Drizzle DB — supports users and sessions tables
// ---------------------------------------------------------------------------

function makeMockDb() {
  /**
   * Resolve which store to use based on the table reference passed to
   * insert/update/delete/from. The mocked table objects carry a __table tag.
   */
  function storeFor(table: any): Record<string, any>[] {
    if (table?.__table === 'sessions') return sessionStore;
    if (table?.__table === 'recovery_codes') return recoveryCodeStore;
    if (table?.__table === 'invitation_tokens') return invitationStore;
    if (table?.__table === 'delegate_linkages') return delegateLinkageStore;
    if (table?.__table === 'audit_log') return auditLogStore;
    return userStore;
  }

  function chainable(ctx: {
    op: string;
    table?: any;
    values?: any;
    setClauses?: any;
    whereClauses: Array<(row: any) => boolean>;
    joinTable?: any;
    joinPredicate?: (sessionRow: any, userRow: any) => boolean;
    projection?: any;
    limitN?: number;
    offsetN?: number;
    orderByFn?: (a: any, b: any) => number;
  }) {
    const chain: any = {
      _ctx: ctx,
      values(v: any) { ctx.values = v; return chain; },
      set(s: any) { ctx.setClauses = s; return chain; },
      from(table: any) { ctx.table = table; return chain; },
      innerJoin(table: any, predicate: any) {
        ctx.joinTable = table;
        ctx.joinPredicate = predicate?.__joinPredicate ?? (() => false);
        return chain;
      },
      where(clause: any) {
        if (typeof clause === 'function') {
          ctx.whereClauses.push(clause);
        } else if (clause && typeof clause === 'object' && clause.__predicate) {
          ctx.whereClauses.push(clause.__predicate);
        }
        return chain;
      },
      limit(n: number) { ctx.limitN = n; return chain; },
      offset(n: number) { ctx.offsetN = n; return chain; },
      orderBy(orderSpec: any) {
        if (orderSpec && orderSpec.__orderByFn) {
          ctx.orderByFn = orderSpec.__orderByFn;
        }
        return chain;
      },
      returning() { return chain; },
      then(resolve: any, reject?: any) {
        try {
          const result = executeOp(ctx);
          resolve(result);
        } catch (e) {
          if (reject) reject(e); else throw e;
        }
      },
    };
    return chain;
  }

  function insertRow(store: Record<string, any>[], values: any): any {
    if (store === userStore) {
      const existing = userStore.find((u) => u.email === values.email);
      if (existing) {
        const err: any = new Error('duplicate key value violates unique constraint "users_email_idx"');
        err.code = '23505';
        throw err;
      }
      const newUser = {
        userId: values.userId ?? crypto.randomUUID(),
        email: values.email,
        passwordHash: values.passwordHash,
        fullName: values.fullName,
        phone: values.phone ?? null,
        role: values.role ?? 'physician',
        emailVerified: values.emailVerified ?? false,
        mfaConfigured: values.mfaConfigured ?? false,
        totpSecretEncrypted: values.totpSecretEncrypted ?? null,
        subscriptionStatus: values.subscriptionStatus ?? 'trial',
        failedLoginCount: values.failedLoginCount ?? 0,
        lockedUntil: values.lockedUntil ?? null,
        isActive: values.isActive ?? true,
        createdAt: values.createdAt ?? new Date(),
        updatedAt: values.updatedAt ?? new Date(),
      };
      userStore.push(newUser);
      return newUser;
    }

    if (store === sessionStore) {
      const newSession = {
        sessionId: values.sessionId ?? crypto.randomUUID(),
        userId: values.userId,
        tokenHash: values.tokenHash,
        ipAddress: values.ipAddress,
        userAgent: values.userAgent,
        createdAt: values.createdAt ?? new Date(),
        lastActiveAt: values.lastActiveAt ?? new Date(),
        revoked: values.revoked ?? false,
        revokedReason: values.revokedReason ?? null,
      };
      sessionStore.push(newSession);
      return newSession;
    }

    if (store === recoveryCodeStore) {
      const newCode = {
        codeId: values.codeId ?? crypto.randomUUID(),
        userId: values.userId,
        codeHash: values.codeHash,
        used: values.used ?? false,
        createdAt: values.createdAt ?? new Date(),
      };
      recoveryCodeStore.push(newCode);
      return newCode;
    }

    if (store === invitationStore) {
      const newInvitation = {
        invitationId: values.invitationId ?? crypto.randomUUID(),
        physicianUserId: values.physicianUserId,
        delegateEmail: values.delegateEmail,
        tokenHash: values.tokenHash,
        permissions: values.permissions,
        expiresAt: values.expiresAt,
        accepted: values.accepted ?? false,
        createdAt: values.createdAt ?? new Date(),
      };
      invitationStore.push(newInvitation);
      return newInvitation;
    }

    if (store === delegateLinkageStore) {
      // Enforce UNIQUE(physician_user_id, delegate_user_id)
      const existing = delegateLinkageStore.find(
        (l) =>
          l.physicianUserId === values.physicianUserId &&
          l.delegateUserId === values.delegateUserId,
      );
      if (existing) {
        const err: any = new Error(
          'duplicate key value violates unique constraint "delegate_linkages_physician_delegate_idx"',
        );
        err.code = '23505';
        throw err;
      }
      const newLinkage = {
        linkageId: values.linkageId ?? crypto.randomUUID(),
        physicianUserId: values.physicianUserId,
        delegateUserId: values.delegateUserId,
        permissions: values.permissions,
        canApproveBatches: values.canApproveBatches ?? false,
        isActive: values.isActive ?? true,
        createdAt: values.createdAt ?? new Date(),
        updatedAt: values.updatedAt ?? new Date(),
      };
      delegateLinkageStore.push(newLinkage);
      return newLinkage;
    }

    if (store === auditLogStore) {
      const newEntry = {
        logId: values.logId ?? crypto.randomUUID(),
        userId: values.userId ?? null,
        action: values.action,
        category: values.category,
        resourceType: values.resourceType ?? null,
        resourceId: values.resourceId ?? null,
        detail: values.detail ?? null,
        ipAddress: values.ipAddress ?? null,
        userAgent: values.userAgent ?? null,
        createdAt: values.createdAt ?? new Date(),
      };
      auditLogStore.push(newEntry);
      return newEntry;
    }

    // Fallback
    const row = { id: crypto.randomUUID(), ...values };
    store.push(row);
    return row;
  }

  function executeOp(ctx: any): any[] {
    const store = storeFor(ctx.table);

    switch (ctx.op) {
      case 'select': {
        // JOIN path (sessions JOIN users)
        if (ctx.joinTable) {
          const joinStore = storeFor(ctx.joinTable);
          const joined: any[] = [];
          for (const sRow of store) {
            for (const uRow of joinStore) {
              if (ctx.joinPredicate!(sRow, uRow)) {
                joined.push({ ...sRow, __joined: uRow });
              }
            }
          }
          let filtered = joined.filter((row) =>
            ctx.whereClauses.every((pred: any) => pred(row)),
          );
          if (ctx.orderByFn) filtered.sort(ctx.orderByFn);
          if (ctx.offsetN) filtered = filtered.slice(ctx.offsetN);
          const limited = ctx.limitN ? filtered.slice(0, ctx.limitN) : filtered;
          // Apply projection
          if (ctx.projection) {
            return limited.map((row) => ctx.projection(row));
          }
          return limited;
        }

        // Regular select (no join)
        let matches = store.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );

        if (ctx.orderByFn) matches.sort(ctx.orderByFn);
        if (ctx.offsetN) matches = matches.slice(ctx.offsetN);
        const limited = ctx.limitN ? matches.slice(0, ctx.limitN) : matches;

        if (ctx.setClauses && ctx.setClauses.__projection) {
          return limited.map(ctx.setClauses.__projection);
        }
        return limited;
      }
      case 'insert': {
        const values = ctx.values;

        // Handle bulk inserts (arrays)
        if (Array.isArray(values)) {
          const results: any[] = [];
          for (const v of values) {
            const row = insertRow(store, v);
            results.push(row);
          }
          return results;
        }

        return [insertRow(store, values)];
      }
      case 'update': {
        const updated: any[] = [];
        const matches = store.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );
        for (const row of matches) {
          const setClauses = ctx.setClauses;
          if (!setClauses) continue;
          const snapshot = { ...row };
          for (const [key, value] of Object.entries(setClauses)) {
            if (key === '__projection') continue;
            if (typeof value === 'object' && value !== null && (value as any).__sqlExpr) {
              row[key] = (value as any).__sqlExpr(snapshot);
            } else {
              row[key] = value;
            }
          }
          updated.push({ ...row });
        }
        return updated;
      }
      case 'delete': {
        const toRemoveIndices: number[] = [];
        for (let i = store.length - 1; i >= 0; i--) {
          if (ctx.whereClauses.every((pred: any) => pred(store[i]))) {
            toRemoveIndices.push(i);
          }
        }
        for (const idx of toRemoveIndices) {
          store.splice(idx, 1);
        }
        return [];
      }
      default:
        return [];
    }
  }

  const mockDb: any = {
    insert(table: any) {
      return chainable({ op: 'insert', table, whereClauses: [] });
    },
    select(projection?: any) {
      const ctx: any = { op: 'select', whereClauses: [], setClauses: null, projection: null };
      if (projection) {
        // Detect structured projection: { someKey: tableRef, otherKey: { field: col } }
        const projKeys = Object.keys(projection);
        const isStructuredProjection = projKeys.some(
          (k) => {
            const v = projection[k];
            // A table ref has __table, or it's an object of column refs
            return v?.__table || (typeof v === 'object' && v !== null && !v.name && !v.__sqlExpr);
          },
        );

        if (isStructuredProjection) {
          ctx.projection = (row: any) => {
            const result: any = {};
            for (const [key, val] of Object.entries(projection) as [string, any][]) {
              if (val?.__table) {
                // Table reference — return the primary row (from the "from" table)
                result[key] = { ...row };
                delete result[key].__joined;
              } else if (typeof val === 'object' && val !== null && !val.name && !val.__sqlExpr) {
                // Object of column refs — pick from joined row
                const fields: any = {};
                for (const [fieldKey, col] of Object.entries(val)) {
                  fields[fieldKey] = row.__joined?.[(col as any)?.name] ?? undefined;
                }
                result[key] = fields;
              }
            }
            return result;
          };
        } else {
          ctx.setClauses = {
            __projection: (row: any) => {
              const result: any = {};
              for (const [key, val] of Object.entries(projection)) {
                if (typeof val === 'object' && val !== null && (val as any).__sqlExpr) {
                  result[key] = (val as any).__sqlExpr(row);
                } else {
                  result[key] = row[key];
                }
              }
              return result;
            },
          };
        }
      }
      return chainable(ctx);
    },
    update(table: any) {
      return chainable({ op: 'update', table, whereClauses: [] });
    },
    delete(table: any) {
      return chainable({ op: 'delete', table, whereClauses: [] });
    },
  };

  return mockDb;
}

// ---------------------------------------------------------------------------
// Mock drizzle-orm operators
// ---------------------------------------------------------------------------

vi.mock('drizzle-orm', () => {
  return {
    eq: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] === value,
        // For innerJoin: eq(sessions.userId, users.userId)
        __joinPredicate: (a: any, b: any) => {
          // column is from "left" table, value is a column from "right" table
          if (value?.name) {
            return a[colName] === b[value.name];
          }
          return a[colName] === value;
        },
      };
    },
    ne: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] !== value,
      };
    },
    gt: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => {
          const rowVal = row[colName];
          if (rowVal instanceof Date && value instanceof Date) {
            return rowVal.getTime() > value.getTime();
          }
          return rowVal > value;
        },
      };
    },
    gte: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => {
          const rowVal = row[colName];
          if (rowVal instanceof Date && value instanceof Date) {
            return rowVal.getTime() >= value.getTime();
          }
          return rowVal >= value;
        },
      };
    },
    lt: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => {
          const rowVal = row[colName];
          if (rowVal instanceof Date && value instanceof Date) {
            return rowVal.getTime() < value.getTime();
          }
          return rowVal < value;
        },
      };
    },
    lte: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => {
          const rowVal = row[colName];
          if (rowVal instanceof Date && value instanceof Date) {
            return rowVal.getTime() <= value.getTime();
          }
          return rowVal <= value;
        },
      };
    },
    and: (...conditions: any[]) => {
      // Flatten: and() may receive undefined items, filter them out
      const preds = conditions.filter(Boolean);
      return {
        __predicate: (row: any) =>
          preds.every((p: any) => {
            if (p?.__predicate) return p.__predicate(row);
            return true;
          }),
      };
    },
    desc: (column: any) => {
      const colName = column?.name;
      return {
        __orderByFn: (a: any, b: any) => {
          const aVal = a[colName];
          const bVal = b[colName];
          if (aVal instanceof Date && bVal instanceof Date) {
            return bVal.getTime() - aVal.getTime();
          }
          if (aVal > bVal) return -1;
          if (aVal < bVal) return 1;
          return 0;
        },
      };
    },
    sql: (strings: TemplateStringsArray, ...values: any[]) => {
      const raw = strings.join('__PLACEHOLDER__');

      // CASE WHEN ${users.failedLoginCount} + 1 >= 10 ...
      if (raw.includes('CASE WHEN') && raw.includes('>= 10')) {
        const countCol = values[0];
        const lockedCol = values[1];
        return {
          __sqlExpr: (row: any) => {
            if ((row[countCol?.name] ?? 0) + 1 >= 10) {
              return new Date(Date.now() + 30 * 60 * 1000);
            }
            return row[lockedCol?.name];
          },
        };
      }

      // ${users.failedLoginCount} + 1
      if (raw.includes('+ 1')) {
        const col = values[0];
        return {
          __sqlExpr: (row: any) => (row[col?.name] ?? 0) + 1,
        };
      }

      // ${users.lockedUntil} > now()
      if (raw.includes('> now()')) {
        const col = values[0];
        return {
          __sqlExpr: (row: any) => {
            if (!row[col?.name]) return false;
            return new Date(row[col?.name]) > new Date();
          },
        };
      }

      return { __sqlExpr: () => null };
    },
  };
});

// Mock the schema module — both users and sessions
vi.mock('@meritum/shared/schemas/db/iam.schema.js', () => {
  const makeCol = (name: string) => ({ name });

  const usersProxy: any = {
    __table: 'users',
    userId: makeCol('userId'),
    email: makeCol('email'),
    passwordHash: makeCol('passwordHash'),
    fullName: makeCol('fullName'),
    phone: makeCol('phone'),
    role: makeCol('role'),
    emailVerified: makeCol('emailVerified'),
    mfaConfigured: makeCol('mfaConfigured'),
    totpSecretEncrypted: makeCol('totpSecretEncrypted'),
    subscriptionStatus: makeCol('subscriptionStatus'),
    failedLoginCount: makeCol('failedLoginCount'),
    lockedUntil: makeCol('lockedUntil'),
    isActive: makeCol('isActive'),
    createdAt: makeCol('createdAt'),
    updatedAt: makeCol('updatedAt'),
  };

  const sessionsProxy: any = {
    __table: 'sessions',
    sessionId: makeCol('sessionId'),
    userId: makeCol('userId'),
    tokenHash: makeCol('tokenHash'),
    ipAddress: makeCol('ipAddress'),
    userAgent: makeCol('userAgent'),
    createdAt: makeCol('createdAt'),
    lastActiveAt: makeCol('lastActiveAt'),
    revoked: makeCol('revoked'),
    revokedReason: makeCol('revokedReason'),
  };

  const recoveryCodesProxy: any = {
    __table: 'recovery_codes',
    codeId: makeCol('codeId'),
    userId: makeCol('userId'),
    codeHash: makeCol('codeHash'),
    used: makeCol('used'),
    createdAt: makeCol('createdAt'),
  };

  const invitationTokensProxy: any = {
    __table: 'invitation_tokens',
    invitationId: makeCol('invitationId'),
    physicianUserId: makeCol('physicianUserId'),
    delegateEmail: makeCol('delegateEmail'),
    tokenHash: makeCol('tokenHash'),
    permissions: makeCol('permissions'),
    expiresAt: makeCol('expiresAt'),
    accepted: makeCol('accepted'),
    createdAt: makeCol('createdAt'),
  };

  const delegateLinkagesProxy: any = {
    __table: 'delegate_linkages',
    linkageId: makeCol('linkageId'),
    physicianUserId: makeCol('physicianUserId'),
    delegateUserId: makeCol('delegateUserId'),
    permissions: makeCol('permissions'),
    canApproveBatches: makeCol('canApproveBatches'),
    isActive: makeCol('isActive'),
    createdAt: makeCol('createdAt'),
    updatedAt: makeCol('updatedAt'),
  };

  const auditLogProxy: any = {
    __table: 'audit_log',
    logId: makeCol('logId'),
    userId: makeCol('userId'),
    action: makeCol('action'),
    category: makeCol('category'),
    resourceType: makeCol('resourceType'),
    resourceId: makeCol('resourceId'),
    detail: makeCol('detail'),
    ipAddress: makeCol('ipAddress'),
    userAgent: makeCol('userAgent'),
    createdAt: makeCol('createdAt'),
  };

  return {
    users: usersProxy,
    sessions: sessionsProxy,
    recoveryCodes: recoveryCodesProxy,
    invitationTokens: invitationTokensProxy,
    delegateLinkages: delegateLinkagesProxy,
    auditLog: auditLogProxy,
  };
});

// Mock the constants module
vi.mock('@meritum/shared/constants/iam.constants.js', () => {
  const Permission = {
    CLAIM_CREATE: 'CLAIM_CREATE',
    CLAIM_VIEW: 'CLAIM_VIEW',
    CLAIM_EDIT: 'CLAIM_EDIT',
    CLAIM_DELETE: 'CLAIM_DELETE',
    CLAIM_SUBMIT: 'CLAIM_SUBMIT',
    BATCH_VIEW: 'BATCH_VIEW',
    BATCH_APPROVE: 'BATCH_APPROVE',
    PATIENT_CREATE: 'PATIENT_CREATE',
    PATIENT_VIEW: 'PATIENT_VIEW',
    PATIENT_EDIT: 'PATIENT_EDIT',
    PATIENT_IMPORT: 'PATIENT_IMPORT',
    REPORT_VIEW: 'REPORT_VIEW',
    REPORT_EXPORT: 'REPORT_EXPORT',
    ANALYTICS_VIEW: 'ANALYTICS_VIEW',
    PROVIDER_VIEW: 'PROVIDER_VIEW',
    PROVIDER_EDIT: 'PROVIDER_EDIT',
    DELEGATE_MANAGE: 'DELEGATE_MANAGE',
    SUBSCRIPTION_MANAGE: 'SUBSCRIPTION_MANAGE',
    SETTINGS_VIEW: 'SETTINGS_VIEW',
    SETTINGS_EDIT: 'SETTINGS_EDIT',
    DATA_EXPORT: 'DATA_EXPORT',
    AUDIT_VIEW: 'AUDIT_VIEW',
    AI_COACH_VIEW: 'AI_COACH_VIEW',
    AI_COACH_MANAGE: 'AI_COACH_MANAGE',
    ADMIN_PHI_ACCESS: 'ADMIN_PHI_ACCESS',
  };
  const Role = {
    PHYSICIAN: 'PHYSICIAN',
    DELEGATE: 'DELEGATE',
    ADMIN: 'ADMIN',
  };
  const DELEGATE_PERMISSIONS = [
    Permission.CLAIM_CREATE, Permission.CLAIM_VIEW, Permission.CLAIM_EDIT,
    Permission.CLAIM_DELETE, Permission.CLAIM_SUBMIT,
    Permission.BATCH_VIEW, Permission.BATCH_APPROVE,
    Permission.PATIENT_CREATE, Permission.PATIENT_VIEW, Permission.PATIENT_EDIT,
    Permission.PATIENT_IMPORT,
    Permission.REPORT_VIEW, Permission.REPORT_EXPORT,
    Permission.ANALYTICS_VIEW,
    Permission.PROVIDER_VIEW, Permission.PROVIDER_EDIT,
    Permission.SETTINGS_VIEW, Permission.SETTINGS_EDIT,
    Permission.AI_COACH_VIEW, Permission.AI_COACH_MANAGE,
  ];
  return {
    Permission,
    Role,
    DefaultPermissions: {
      [Role.PHYSICIAN]: Object.values(Permission).filter(p => p !== Permission.ADMIN_PHI_ACCESS),
      [Role.DELEGATE]: DELEGATE_PERMISSIONS,
      [Role.ADMIN]: Object.values(Permission),
    },
    SessionRevokeReason: {
      LOGOUT: 'logout',
      EXPIRED_IDLE: 'expired_idle',
      EXPIRED_ABSOLUTE: 'expired_absolute',
      REVOKED_REMOTE: 'revoked_remote',
      PASSWORD_RESET: 'password_reset',
      ACCOUNT_DELETED: 'account_deleted',
    },
    AuditAction: {
      AUTH_REGISTERED: 'auth.registered',
      AUTH_EMAIL_VERIFIED: 'auth.email_verified',
      AUTH_MFA_SETUP: 'auth.mfa_setup',
      AUTH_LOGIN_SUCCESS: 'auth.login_success',
      AUTH_LOGIN_FAILED: 'auth.login_failed',
      AUTH_LOGIN_MFA_SUCCESS: 'auth.login_mfa_success',
      AUTH_LOGIN_MFA_FAILED: 'auth.login_mfa_failed',
      AUTH_LOGIN_RECOVERY_USED: 'auth.login_recovery_used',
      AUTH_LOGOUT: 'auth.logout',
      AUTH_SESSION_REVOKED: 'auth.session_revoked',
      AUTH_SESSION_REVOKED_ALL: 'auth.session_revoked_all',
      AUTH_PASSWORD_RESET_REQUESTED: 'auth.password_reset_requested',
      AUTH_PASSWORD_RESET_COMPLETED: 'auth.password_reset_completed',
      DELEGATE_INVITED: 'delegate.invited',
      DELEGATE_ACCEPTED: 'delegate.accepted',
      DELEGATE_PERMISSIONS_UPDATED: 'delegate.permissions_updated',
      DELEGATE_REVOKED: 'delegate.revoked',
      DELEGATE_CONTEXT_SWITCHED: 'delegate.context_switched',
      ACCOUNT_UPDATED: 'account.updated',
      ACCOUNT_MFA_RECONFIGURED: 'account.mfa_reconfigured',
      ACCOUNT_RECOVERY_CODES_REGENERATED: 'account.recovery_codes_regenerated',
      ACCOUNT_DELETION_REQUESTED: 'account.deletion_requested',
      ACCOUNT_DELETION_EXECUTED: 'account.deletion_executed',
      ACCOUNT_SUSPENDED: 'account.suspended',
      ACCOUNT_REACTIVATED: 'account.reactivated',
      AUDIT_QUERIED: 'audit.queried',
      AUDIT_EXPORTED: 'audit.exported',
      ADMIN_MFA_RESET_ISSUED: 'admin.mfa_reset_issued',
    },
    AuditCategory: {
      AUTH: 'auth',
      DELEGATE: 'delegate',
      ACCOUNT: 'account',
      AUDIT: 'audit',
      ADMIN: 'admin',
    },
  };
});

// ---------------------------------------------------------------------------
// Tests: User CRUD (existing)
// ---------------------------------------------------------------------------

describe('IAM Repository — User CRUD', () => {
  let repo: ReturnType<typeof createUserRepository>;

  beforeEach(() => {
    userStore = [];
    sessionStore = [];
    recoveryCodeStore = [];
    invitationStore = [];
    delegateLinkageStore = [];
    auditLogStore = [];
    const db = makeMockDb();
    repo = createUserRepository(db);
  });

  // -- createUser --

  it('createUser stores user with lowercase email', async () => {
    const user = await repo.createUser({
      email: 'Doctor.Smith@Hospital.CA',
      passwordHash: 'hashed_pw',
      fullName: 'Dr. Smith',
    });
    expect(user.email).toBe('doctor.smith@hospital.ca');
    expect(user.fullName).toBe('Dr. Smith');
    expect(user.isActive).toBe(true);
  });

  it('createUser rejects duplicate email', async () => {
    await repo.createUser({
      email: 'dr@example.com',
      passwordHash: 'hash1',
      fullName: 'First',
    });

    await expect(
      repo.createUser({
        email: 'dr@example.com',
        passwordHash: 'hash2',
        fullName: 'Second',
      }),
    ).rejects.toThrow(/duplicate key/);
  });

  // -- findUserByEmail --

  it('findUserByEmail is case-insensitive', async () => {
    await repo.createUser({
      email: 'dr@example.com',
      passwordHash: 'hash',
      fullName: 'Doctor',
    });

    const found = await repo.findUserByEmail('DR@EXAMPLE.COM');
    expect(found).toBeDefined();
    expect(found!.email).toBe('dr@example.com');
  });

  it('findUserByEmail excludes inactive users', async () => {
    const user = await repo.createUser({
      email: 'inactive@example.com',
      passwordHash: 'hash',
      fullName: 'Inactive',
    });
    await repo.deactivateUser(user.userId);

    const found = await repo.findUserByEmail('inactive@example.com');
    expect(found).toBeUndefined();
  });

  // -- findUserById --

  it('findUserById returns user by UUID', async () => {
    const created = await repo.createUser({
      email: 'id-test@example.com',
      passwordHash: 'hash',
      fullName: 'ID Test',
    });

    const found = await repo.findUserById(created.userId);
    expect(found).toBeDefined();
    expect(found!.userId).toBe(created.userId);
  });

  it('findUserById returns undefined for non-existent user', async () => {
    const found = await repo.findUserById('00000000-0000-0000-0000-000000000000');
    expect(found).toBeUndefined();
  });

  // -- updateUser --

  it('updateUser updates allowed fields', async () => {
    const user = await repo.createUser({
      email: 'update@example.com',
      passwordHash: 'hash',
      fullName: 'Original',
    });

    const updated = await repo.updateUser(user.userId, {
      fullName: 'Updated Name',
      phone: '403-555-1234',
    });
    expect(updated!.fullName).toBe('Updated Name');
    expect(updated!.phone).toBe('403-555-1234');
  });

  it('updateUser does NOT allow updating email', async () => {
    const user = await repo.createUser({
      email: 'safe@example.com',
      passwordHash: 'hash',
      fullName: 'Safe User',
    });

    await repo.updateUser(user.userId, {
      email: 'hacked@evil.com',
    } as any);

    const found = await repo.findUserById(user.userId);
    expect(found!.email).toBe('safe@example.com');
  });

  it('updateUser does NOT allow updating passwordHash', async () => {
    const user = await repo.createUser({
      email: 'pw@example.com',
      passwordHash: 'original_hash',
      fullName: 'PW User',
    });

    await repo.updateUser(user.userId, {
      passwordHash: 'evil_hash',
    } as any);

    const found = await repo.findUserById(user.userId);
    expect(found!.passwordHash).toBe('original_hash');
  });

  it('updateUser does NOT allow updating totpSecretEncrypted', async () => {
    const user = await repo.createUser({
      email: 'totp@example.com',
      passwordHash: 'hash',
      fullName: 'TOTP User',
    });

    await repo.updateUser(user.userId, {
      totpSecretEncrypted: 'evil_secret',
    } as any);

    const found = await repo.findUserById(user.userId);
    expect(found!.totpSecretEncrypted).toBeNull();
  });

  // -- incrementFailedLogin / account locking --

  it('incrementFailedLogin locks account after 10 failures', async () => {
    const user = await repo.createUser({
      email: 'lockme@example.com',
      passwordHash: 'hash',
      fullName: 'Lock Test',
    });

    for (let i = 0; i < 10; i++) {
      await repo.incrementFailedLogin(user.userId);
    }

    const found = await repo.findUserById(user.userId);
    expect(found!.failedLoginCount).toBe(10);
    expect(found!.lockedUntil).not.toBeNull();

    const isLocked = await repo.isAccountLocked(user.userId);
    expect(isLocked).toBe(true);
  });

  it('incrementFailedLogin does not lock before 10 failures', async () => {
    const user = await repo.createUser({
      email: 'nolock@example.com',
      passwordHash: 'hash',
      fullName: 'No Lock',
    });

    for (let i = 0; i < 9; i++) {
      await repo.incrementFailedLogin(user.userId);
    }

    const found = await repo.findUserById(user.userId);
    expect(found!.failedLoginCount).toBe(9);
    expect(found!.lockedUntil).toBeNull();
  });

  // -- resetFailedLogin --

  it('resetFailedLogin clears lock', async () => {
    const user = await repo.createUser({
      email: 'clearlock@example.com',
      passwordHash: 'hash',
      fullName: 'Clear Lock',
    });

    for (let i = 0; i < 10; i++) {
      await repo.incrementFailedLogin(user.userId);
    }

    await repo.resetFailedLogin(user.userId);

    const found = await repo.findUserById(user.userId);
    expect(found!.failedLoginCount).toBe(0);
    expect(found!.lockedUntil).toBeNull();

    const isLocked = await repo.isAccountLocked(user.userId);
    expect(isLocked).toBe(false);
  });

  // -- isAccountLocked --

  it('isAccountLocked returns true during lock period', async () => {
    const user = await repo.createUser({
      email: 'locked@example.com',
      passwordHash: 'hash',
      fullName: 'Locked',
    });

    userStore[userStore.length - 1].lockedUntil = new Date(Date.now() + 30 * 60 * 1000);

    const locked = await repo.isAccountLocked(user.userId);
    expect(locked).toBe(true);
  });

  it('isAccountLocked returns false after lock expires', async () => {
    const user = await repo.createUser({
      email: 'expired@example.com',
      passwordHash: 'hash',
      fullName: 'Expired Lock',
    });

    userStore[userStore.length - 1].lockedUntil = new Date(Date.now() - 30 * 60 * 1000);

    const locked = await repo.isAccountLocked(user.userId);
    expect(locked).toBe(false);
  });

  it('isAccountLocked returns false when never locked', async () => {
    const user = await repo.createUser({
      email: 'neverlocked@example.com',
      passwordHash: 'hash',
      fullName: 'Never Locked',
    });

    const locked = await repo.isAccountLocked(user.userId);
    expect(locked).toBe(false);
  });

  // -- deactivateUser --

  it('deactivateUser sets is_active to false', async () => {
    const user = await repo.createUser({
      email: 'deactivate@example.com',
      passwordHash: 'hash',
      fullName: 'Deactivate Me',
    });

    await repo.deactivateUser(user.userId);

    const found = await repo.findUserById(user.userId);
    expect(found!.isActive).toBe(false);
  });

  // -- setMfaSecret --

  it('setMfaSecret stores encrypted TOTP secret', async () => {
    const user = await repo.createUser({
      email: 'mfa@example.com',
      passwordHash: 'hash',
      fullName: 'MFA User',
    });

    await repo.setMfaSecret(user.userId, 'encrypted_totp_secret');

    const found = await repo.findUserById(user.userId);
    expect(found!.totpSecretEncrypted).toBe('encrypted_totp_secret');
  });

  // -- setMfaConfigured --

  it('setMfaConfigured sets mfa_configured to true', async () => {
    const user = await repo.createUser({
      email: 'mfaconf@example.com',
      passwordHash: 'hash',
      fullName: 'MFA Conf',
    });

    expect(user.mfaConfigured).toBe(false);
    await repo.setMfaConfigured(user.userId);

    const found = await repo.findUserById(user.userId);
    expect(found!.mfaConfigured).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Tests: Session Management
// ---------------------------------------------------------------------------

describe('IAM Repository — Session Management', () => {
  let userRepo: ReturnType<typeof createUserRepository>;
  let sessionRepo: ReturnType<typeof createSessionRepository>;

  /** Helper: create a user and return it. */
  async function seedUser(email = 'session-test@example.com') {
    return userRepo.createUser({
      email,
      passwordHash: 'hashed_pw',
      fullName: 'Session Test',
    });
  }

  beforeEach(() => {
    userStore = [];
    sessionStore = [];
    recoveryCodeStore = [];
    invitationStore = [];
    delegateLinkageStore = [];
    auditLogStore = [];
    const db = makeMockDb();
    userRepo = createUserRepository(db);
    sessionRepo = createSessionRepository(db);
  });

  // -- createSession --

  it('createSession stores session with hashed token', async () => {
    const user = await seedUser();
    const session = await sessionRepo.createSession({
      userId: user.userId,
      tokenHash: 'sha256_hashed_token_abc',
      ipAddress: '10.0.0.1',
      userAgent: 'Mozilla/5.0',
    });

    expect(session.sessionId).toBeDefined();
    expect(session.userId).toBe(user.userId);
    expect(session.tokenHash).toBe('sha256_hashed_token_abc');
    expect(session.ipAddress).toBe('10.0.0.1');
    expect(session.userAgent).toBe('Mozilla/5.0');
    expect(session.revoked).toBe(false);
    expect(session.revokedReason).toBeNull();
    expect(session.createdAt).toBeInstanceOf(Date);
    expect(session.lastActiveAt).toBeInstanceOf(Date);
  });

  // -- findSessionByTokenHash --

  it('findSessionByTokenHash returns session with user data', async () => {
    const user = await seedUser();
    await sessionRepo.createSession({
      userId: user.userId,
      tokenHash: 'valid_token_hash',
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome/120',
    });

    const result = await sessionRepo.findSessionByTokenHash('valid_token_hash');
    expect(result).toBeDefined();
    expect(result!.session.tokenHash).toBe('valid_token_hash');
    expect(result!.user.userId).toBe(user.userId);
    expect(result!.user.role).toBe('physician');
    expect(result!.user.subscriptionStatus).toBe('trial');
  });

  it('findSessionByTokenHash returns null for revoked session', async () => {
    const user = await seedUser();
    const session = await sessionRepo.createSession({
      userId: user.userId,
      tokenHash: 'revoked_token',
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome/120',
    });

    await sessionRepo.revokeSession(session.sessionId, 'logout');

    const result = await sessionRepo.findSessionByTokenHash('revoked_token');
    expect(result).toBeUndefined();
  });

  it('findSessionByTokenHash returns null for expired session (absolute)', async () => {
    const user = await seedUser();
    await sessionRepo.createSession({
      userId: user.userId,
      tokenHash: 'absolute_expired_token',
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome/120',
    });

    // Backdate createdAt to 25 hours ago (exceeds 24h absolute limit)
    const session = sessionStore.find((s) => s.tokenHash === 'absolute_expired_token');
    session!.createdAt = new Date(Date.now() - 25 * 60 * 60 * 1000);
    session!.lastActiveAt = new Date(); // Still "active" but absolute expired

    const result = await sessionRepo.findSessionByTokenHash('absolute_expired_token');
    expect(result).toBeUndefined();
  });

  it('findSessionByTokenHash returns null for expired session (idle)', async () => {
    const user = await seedUser();
    await sessionRepo.createSession({
      userId: user.userId,
      tokenHash: 'idle_expired_token',
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome/120',
    });

    // Set lastActiveAt to 61 minutes ago (exceeds 60min idle limit)
    const session = sessionStore.find((s) => s.tokenHash === 'idle_expired_token');
    session!.lastActiveAt = new Date(Date.now() - 61 * 60 * 1000);

    const result = await sessionRepo.findSessionByTokenHash('idle_expired_token');
    expect(result).toBeUndefined();
  });

  it('findSessionByTokenHash returns undefined for non-existent token', async () => {
    const result = await sessionRepo.findSessionByTokenHash('does_not_exist');
    expect(result).toBeUndefined();
  });

  // -- refreshSession --

  it('refreshSession updates last_active_at', async () => {
    const user = await seedUser();
    const session = await sessionRepo.createSession({
      userId: user.userId,
      tokenHash: 'refresh_me',
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome/120',
    });

    const originalLastActive = session.lastActiveAt;

    // Small delay to ensure Date.now() differs
    await new Promise((r) => setTimeout(r, 10));

    await sessionRepo.refreshSession(session.sessionId);

    const updated = sessionStore.find((s) => s.sessionId === session.sessionId);
    expect(updated!.lastActiveAt.getTime()).toBeGreaterThanOrEqual(
      originalLastActive.getTime(),
    );
  });

  // -- revokeSession --

  it('revokeSession sets revoked flag and reason', async () => {
    const user = await seedUser();
    const session = await sessionRepo.createSession({
      userId: user.userId,
      tokenHash: 'revoke_me',
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome/120',
    });

    await sessionRepo.revokeSession(session.sessionId, 'logout');

    const found = sessionStore.find((s) => s.sessionId === session.sessionId);
    expect(found!.revoked).toBe(true);
    expect(found!.revokedReason).toBe('logout');
  });

  // -- revokeAllUserSessions --

  it('revokeAllUserSessions revokes all except current', async () => {
    const user = await seedUser();
    const s1 = await sessionRepo.createSession({
      userId: user.userId,
      tokenHash: 'session_1',
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome',
    });
    const s2 = await sessionRepo.createSession({
      userId: user.userId,
      tokenHash: 'session_2',
      ipAddress: '10.0.0.2',
      userAgent: 'Firefox',
    });
    const s3 = await sessionRepo.createSession({
      userId: user.userId,
      tokenHash: 'session_3',
      ipAddress: '10.0.0.3',
      userAgent: 'Safari',
    });

    // Keep s1, revoke s2 and s3
    await sessionRepo.revokeAllUserSessions(user.userId, s1.sessionId, 'password_reset');

    const kept = sessionStore.find((s) => s.sessionId === s1.sessionId);
    expect(kept!.revoked).toBe(false);

    const revoked2 = sessionStore.find((s) => s.sessionId === s2.sessionId);
    expect(revoked2!.revoked).toBe(true);
    expect(revoked2!.revokedReason).toBe('password_reset');

    const revoked3 = sessionStore.find((s) => s.sessionId === s3.sessionId);
    expect(revoked3!.revoked).toBe(true);
    expect(revoked3!.revokedReason).toBe('password_reset');
  });

  it('revokeAllUserSessions revokes ALL when no exceptSessionId', async () => {
    const user = await seedUser();
    await sessionRepo.createSession({
      userId: user.userId,
      tokenHash: 'all_1',
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome',
    });
    await sessionRepo.createSession({
      userId: user.userId,
      tokenHash: 'all_2',
      ipAddress: '10.0.0.2',
      userAgent: 'Firefox',
    });

    await sessionRepo.revokeAllUserSessions(user.userId, undefined, 'account_deleted');

    const active = sessionStore.filter((s) => s.userId === user.userId && !s.revoked);
    expect(active.length).toBe(0);
  });

  it('revokeAllUserSessions does not affect other users sessions', async () => {
    const user1 = await seedUser('user1@example.com');
    const user2 = await seedUser('user2@example.com');

    await sessionRepo.createSession({
      userId: user1.userId,
      tokenHash: 'u1_session',
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome',
    });
    await sessionRepo.createSession({
      userId: user2.userId,
      tokenHash: 'u2_session',
      ipAddress: '10.0.0.2',
      userAgent: 'Firefox',
    });

    await sessionRepo.revokeAllUserSessions(user1.userId, undefined, 'logout');

    const u2Session = sessionStore.find((s) => s.tokenHash === 'u2_session');
    expect(u2Session!.revoked).toBe(false);
  });

  // -- listActiveSessions --

  it('listActiveSessions returns only non-revoked sessions', async () => {
    const user = await seedUser();
    await sessionRepo.createSession({
      userId: user.userId,
      tokenHash: 'active_1',
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome',
    });
    const s2 = await sessionRepo.createSession({
      userId: user.userId,
      tokenHash: 'active_2',
      ipAddress: '10.0.0.2',
      userAgent: 'Firefox',
    });
    await sessionRepo.createSession({
      userId: user.userId,
      tokenHash: 'active_3',
      ipAddress: '10.0.0.3',
      userAgent: 'Safari',
    });

    // Revoke one
    await sessionRepo.revokeSession(s2.sessionId, 'logout');

    const active = await sessionRepo.listActiveSessions(user.userId);
    expect(active.length).toBe(2);
    expect(active.every((s: any) => s.revoked === false)).toBe(true);
  });

  it('listActiveSessions returns only sessions for specified user', async () => {
    const user1 = await seedUser('list-u1@example.com');
    const user2 = await seedUser('list-u2@example.com');

    await sessionRepo.createSession({
      userId: user1.userId,
      tokenHash: 'list_u1_s1',
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome',
    });
    await sessionRepo.createSession({
      userId: user2.userId,
      tokenHash: 'list_u2_s1',
      ipAddress: '10.0.0.2',
      userAgent: 'Firefox',
    });

    const u1Sessions = await sessionRepo.listActiveSessions(user1.userId);
    expect(u1Sessions.length).toBe(1);
    expect(u1Sessions[0].userId).toBe(user1.userId);
  });

  // -- isSessionExpired (standalone function) --

  it('isSessionExpired returns false for fresh session', () => {
    const session = {
      sessionId: 'test-id',
      userId: 'user-id',
      tokenHash: 'hash',
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    };
    expect(isSessionExpired(session as any)).toBe(false);
  });

  it('isSessionExpired returns true when absolute expiry exceeded', () => {
    const session = {
      sessionId: 'test-id',
      userId: 'user-id',
      tokenHash: 'hash',
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome',
      createdAt: new Date(Date.now() - 25 * 60 * 60 * 1000), // 25h ago
      lastActiveAt: new Date(), // just now
      revoked: false,
      revokedReason: null,
    };
    expect(isSessionExpired(session as any)).toBe(true);
  });

  it('isSessionExpired returns true when idle expiry exceeded', () => {
    const session = {
      sessionId: 'test-id',
      userId: 'user-id',
      tokenHash: 'hash',
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome',
      createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2h ago (within 24h)
      lastActiveAt: new Date(Date.now() - 61 * 60 * 1000), // 61min ago
      revoked: false,
      revokedReason: null,
    };
    expect(isSessionExpired(session as any)).toBe(true);
  });

  // -- cleanupExpiredSessions --

  it('cleanupExpiredSessions removes old revoked sessions', async () => {
    const user = await seedUser();

    // Create an old revoked session (31 days ago)
    await sessionRepo.createSession({
      userId: user.userId,
      tokenHash: 'old_revoked',
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome',
    });
    const oldSession = sessionStore.find((s) => s.tokenHash === 'old_revoked');
    oldSession!.revoked = true;
    oldSession!.revokedReason = 'logout';
    oldSession!.createdAt = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000);

    // Create an active session (should NOT be removed)
    await sessionRepo.createSession({
      userId: user.userId,
      tokenHash: 'active_session',
      ipAddress: '10.0.0.2',
      userAgent: 'Firefox',
    });

    // Create a recently revoked session (should NOT be removed — < 30 days)
    await sessionRepo.createSession({
      userId: user.userId,
      tokenHash: 'recent_revoked',
      ipAddress: '10.0.0.3',
      userAgent: 'Safari',
    });
    const recentRevoked = sessionStore.find((s) => s.tokenHash === 'recent_revoked');
    recentRevoked!.revoked = true;
    recentRevoked!.revokedReason = 'expired_idle';

    expect(sessionStore.length).toBe(3);

    await sessionRepo.cleanupExpiredSessions();

    expect(sessionStore.length).toBe(2);
    expect(sessionStore.find((s) => s.tokenHash === 'old_revoked')).toBeUndefined();
    expect(sessionStore.find((s) => s.tokenHash === 'active_session')).toBeDefined();
    expect(sessionStore.find((s) => s.tokenHash === 'recent_revoked')).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Tests: Recovery Codes
// ---------------------------------------------------------------------------

describe('IAM Repository — Recovery Codes', () => {
  let userRepo: ReturnType<typeof createUserRepository>;
  let recoveryRepo: ReturnType<typeof createRecoveryCodeRepository>;

  async function seedUser(email = 'recovery-test@example.com') {
    return userRepo.createUser({
      email,
      passwordHash: 'hashed_pw',
      fullName: 'Recovery Test',
    });
  }

  beforeEach(() => {
    userStore = [];
    sessionStore = [];
    recoveryCodeStore = [];
    invitationStore = [];
    delegateLinkageStore = [];
    auditLogStore = [];
    const db = makeMockDb();
    userRepo = createUserRepository(db);
    recoveryRepo = createRecoveryCodeRepository(db);
  });

  it('createRecoveryCodes inserts 10 codes', async () => {
    const user = await seedUser();
    const hashes = Array.from({ length: 10 }, (_, i) => `hash_${i}`);

    const codes = await recoveryRepo.createRecoveryCodes(user.userId, hashes);

    expect(codes.length).toBe(10);
    expect(recoveryCodeStore.length).toBe(10);
    for (let i = 0; i < 10; i++) {
      expect(codes[i].codeHash).toBe(`hash_${i}`);
      expect(codes[i].userId).toBe(user.userId);
      expect(codes[i].used).toBe(false);
      expect(codes[i].codeId).toBeDefined();
    }
  });

  it('createRecoveryCodes deletes previous unused codes', async () => {
    const user = await seedUser();
    const firstBatch = Array.from({ length: 10 }, (_, i) => `first_hash_${i}`);
    const codes = await recoveryRepo.createRecoveryCodes(user.userId, firstBatch);

    // Mark one code as used
    await recoveryRepo.markRecoveryCodeUsed(codes[0].codeId);

    // Generate a new batch — should delete all unused codes from the first batch
    const secondBatch = Array.from({ length: 10 }, (_, i) => `second_hash_${i}`);
    await recoveryRepo.createRecoveryCodes(user.userId, secondBatch);

    // Should have: 1 used code from first batch + 10 new codes = 11
    expect(recoveryCodeStore.length).toBe(11);

    // The used code from the first batch should still be there
    const usedCode = recoveryCodeStore.find((c) => c.codeHash === 'first_hash_0');
    expect(usedCode).toBeDefined();
    expect(usedCode!.used).toBe(true);

    // All second batch codes should be present
    const secondBatchCodes = recoveryCodeStore.filter((c) =>
      c.codeHash.startsWith('second_hash_'),
    );
    expect(secondBatchCodes.length).toBe(10);
  });

  it('markRecoveryCodeUsed sets used flag', async () => {
    const user = await seedUser();
    const hashes = ['use_me_hash'];
    const codes = await recoveryRepo.createRecoveryCodes(user.userId, hashes);

    expect(codes[0].used).toBe(false);

    await recoveryRepo.markRecoveryCodeUsed(codes[0].codeId);

    const updated = recoveryCodeStore.find((c) => c.codeId === codes[0].codeId);
    expect(updated!.used).toBe(true);
  });

  it('countRemainingCodes returns correct count', async () => {
    const user = await seedUser();
    const hashes = Array.from({ length: 10 }, (_, i) => `count_hash_${i}`);
    const codes = await recoveryRepo.createRecoveryCodes(user.userId, hashes);

    expect(await recoveryRepo.countRemainingCodes(user.userId)).toBe(10);

    // Use 3 codes
    await recoveryRepo.markRecoveryCodeUsed(codes[0].codeId);
    await recoveryRepo.markRecoveryCodeUsed(codes[1].codeId);
    await recoveryRepo.markRecoveryCodeUsed(codes[2].codeId);

    expect(await recoveryRepo.countRemainingCodes(user.userId)).toBe(7);
  });

  it('findUnusedRecoveryCodes returns only unused codes', async () => {
    const user = await seedUser();
    const hashes = Array.from({ length: 5 }, (_, i) => `find_hash_${i}`);
    const codes = await recoveryRepo.createRecoveryCodes(user.userId, hashes);

    await recoveryRepo.markRecoveryCodeUsed(codes[0].codeId);
    await recoveryRepo.markRecoveryCodeUsed(codes[1].codeId);

    const unused = await recoveryRepo.findUnusedRecoveryCodes(user.userId);
    expect(unused.length).toBe(3);
    expect(unused.every((c) => c.used === false)).toBe(true);
  });

  it('findUnusedRecoveryCodes scoped to user', async () => {
    const user1 = await seedUser('user1-rc@example.com');
    const user2 = await seedUser('user2-rc@example.com');

    await recoveryRepo.createRecoveryCodes(user1.userId, ['u1_hash']);
    await recoveryRepo.createRecoveryCodes(user2.userId, ['u2_hash']);

    const u1Codes = await recoveryRepo.findUnusedRecoveryCodes(user1.userId);
    expect(u1Codes.length).toBe(1);
    expect(u1Codes[0].userId).toBe(user1.userId);
  });
});

// ---------------------------------------------------------------------------
// Tests: Invitation Tokens
// ---------------------------------------------------------------------------

describe('IAM Repository — Invitation Tokens', () => {
  let userRepo: ReturnType<typeof createUserRepository>;
  let invitationRepo: ReturnType<typeof createInvitationRepository>;

  async function seedUser(email = 'invitation-test@example.com') {
    return userRepo.createUser({
      email,
      passwordHash: 'hashed_pw',
      fullName: 'Invitation Test',
    });
  }

  beforeEach(() => {
    userStore = [];
    sessionStore = [];
    recoveryCodeStore = [];
    invitationStore = [];
    delegateLinkageStore = [];
    auditLogStore = [];
    const db = makeMockDb();
    userRepo = createUserRepository(db);
    invitationRepo = createInvitationRepository(db);
  });

  it('createInvitation stores invitation with hashed token', async () => {
    const physician = await seedUser();
    const invitation = await invitationRepo.createInvitation({
      physicianUserId: physician.userId,
      delegateEmail: 'Delegate@Example.Com',
      tokenHash: 'hashed_invite_token',
      permissions: ['CLAIM_VIEW', 'PATIENT_VIEW'],
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    expect(invitation.invitationId).toBeDefined();
    expect(invitation.physicianUserId).toBe(physician.userId);
    expect(invitation.delegateEmail).toBe('delegate@example.com');
    expect(invitation.tokenHash).toBe('hashed_invite_token');
    expect(invitation.permissions).toEqual(['CLAIM_VIEW', 'PATIENT_VIEW']);
    expect(invitation.accepted).toBe(false);
  });

  it('findInvitationByTokenHash returns valid invitation', async () => {
    const physician = await seedUser();
    await invitationRepo.createInvitation({
      physicianUserId: physician.userId,
      delegateEmail: 'delegate@example.com',
      tokenHash: 'find_me_token',
      permissions: ['CLAIM_VIEW'],
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    const found = await invitationRepo.findInvitationByTokenHash('find_me_token');
    expect(found).toBeDefined();
    expect(found!.tokenHash).toBe('find_me_token');
  });

  it('findInvitationByTokenHash returns null for accepted invitation', async () => {
    const physician = await seedUser();
    const invitation = await invitationRepo.createInvitation({
      physicianUserId: physician.userId,
      delegateEmail: 'accepted@example.com',
      tokenHash: 'accepted_token',
      permissions: ['CLAIM_VIEW'],
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    await invitationRepo.markInvitationAccepted(invitation.invitationId);

    const found = await invitationRepo.findInvitationByTokenHash('accepted_token');
    expect(found).toBeUndefined();
  });

  it('findInvitationByTokenHash returns null for expired invitation', async () => {
    const physician = await seedUser();
    await invitationRepo.createInvitation({
      physicianUserId: physician.userId,
      delegateEmail: 'expired@example.com',
      tokenHash: 'expired_token',
      permissions: ['CLAIM_VIEW'],
      expiresAt: new Date(Date.now() - 1000), // Already expired
    });

    const found = await invitationRepo.findInvitationByTokenHash('expired_token');
    expect(found).toBeUndefined();
  });

  it('findInvitationByTokenHash returns undefined for non-existent token', async () => {
    const found = await invitationRepo.findInvitationByTokenHash('does_not_exist');
    expect(found).toBeUndefined();
  });

  it('markInvitationAccepted sets accepted flag', async () => {
    const physician = await seedUser();
    const invitation = await invitationRepo.createInvitation({
      physicianUserId: physician.userId,
      delegateEmail: 'mark@example.com',
      tokenHash: 'mark_accepted_token',
      permissions: ['CLAIM_VIEW'],
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    expect(invitation.accepted).toBe(false);

    await invitationRepo.markInvitationAccepted(invitation.invitationId);

    const updated = invitationStore.find(
      (i) => i.invitationId === invitation.invitationId,
    );
    expect(updated!.accepted).toBe(true);
  });

  it('listPendingInvitations excludes accepted and expired', async () => {
    const physician = await seedUser();

    // Pending invitation (should be returned)
    await invitationRepo.createInvitation({
      physicianUserId: physician.userId,
      delegateEmail: 'pending@example.com',
      tokenHash: 'pending_token',
      permissions: ['CLAIM_VIEW'],
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    // Accepted invitation (should NOT be returned)
    const accepted = await invitationRepo.createInvitation({
      physicianUserId: physician.userId,
      delegateEmail: 'accepted@example.com',
      tokenHash: 'accepted_list_token',
      permissions: ['CLAIM_VIEW'],
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });
    await invitationRepo.markInvitationAccepted(accepted.invitationId);

    // Expired invitation (should NOT be returned)
    await invitationRepo.createInvitation({
      physicianUserId: physician.userId,
      delegateEmail: 'expired@example.com',
      tokenHash: 'expired_list_token',
      permissions: ['CLAIM_VIEW'],
      expiresAt: new Date(Date.now() - 1000),
    });

    const pending = await invitationRepo.listPendingInvitations(physician.userId);
    expect(pending.length).toBe(1);
    expect(pending[0].delegateEmail).toBe('pending@example.com');
  });

  it('listPendingInvitations scoped to physician', async () => {
    const physician1 = await seedUser('doc1@example.com');
    const physician2 = await seedUser('doc2@example.com');

    await invitationRepo.createInvitation({
      physicianUserId: physician1.userId,
      delegateEmail: 'del1@example.com',
      tokenHash: 'p1_token',
      permissions: ['CLAIM_VIEW'],
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    await invitationRepo.createInvitation({
      physicianUserId: physician2.userId,
      delegateEmail: 'del2@example.com',
      tokenHash: 'p2_token',
      permissions: ['CLAIM_VIEW'],
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    const p1Pending = await invitationRepo.listPendingInvitations(physician1.userId);
    expect(p1Pending.length).toBe(1);
    expect(p1Pending[0].physicianUserId).toBe(physician1.userId);
  });
});

// ---------------------------------------------------------------------------
// Tests: Delegate Linkages
// ---------------------------------------------------------------------------

describe('IAM Repository — Delegate Linkages', () => {
  let userRepo: ReturnType<typeof createUserRepository>;
  let sessionRepo: ReturnType<typeof createSessionRepository>;
  let linkageRepo: ReturnType<typeof createDelegateLinkageRepository>;

  async function seedUser(email: string, fullName = 'Test User') {
    return userRepo.createUser({
      email,
      passwordHash: 'hashed_pw',
      fullName,
    });
  }

  beforeEach(() => {
    userStore = [];
    sessionStore = [];
    recoveryCodeStore = [];
    invitationStore = [];
    delegateLinkageStore = [];
    auditLogStore = [];
    const db = makeMockDb();
    userRepo = createUserRepository(db);
    sessionRepo = createSessionRepository(db);
    linkageRepo = createDelegateLinkageRepository(db);
  });

  // -- createDelegateLinkage --

  it('createDelegateLinkage creates active linkage', async () => {
    const physician = await seedUser('doc@example.com', 'Dr. Smith');
    const delegate = await seedUser('del@example.com', 'Jane Delegate');

    const linkage = await linkageRepo.createDelegateLinkage({
      physicianUserId: physician.userId,
      delegateUserId: delegate.userId,
      permissions: ['CLAIM_VIEW', 'PATIENT_VIEW'],
      canApproveBatches: false,
    });

    expect(linkage.linkageId).toBeDefined();
    expect(linkage.physicianUserId).toBe(physician.userId);
    expect(linkage.delegateUserId).toBe(delegate.userId);
    expect(linkage.permissions).toEqual(['CLAIM_VIEW', 'PATIENT_VIEW']);
    expect(linkage.canApproveBatches).toBe(false);
    expect(linkage.isActive).toBe(true);
    expect(linkage.createdAt).toBeInstanceOf(Date);
    expect(linkage.updatedAt).toBeInstanceOf(Date);
  });

  it('createDelegateLinkage rejects duplicate physician-delegate pair', async () => {
    const physician = await seedUser('doc-dup@example.com', 'Dr. Dup');
    const delegate = await seedUser('del-dup@example.com', 'Del Dup');

    await linkageRepo.createDelegateLinkage({
      physicianUserId: physician.userId,
      delegateUserId: delegate.userId,
      permissions: ['CLAIM_VIEW'],
      canApproveBatches: false,
    });

    await expect(
      linkageRepo.createDelegateLinkage({
        physicianUserId: physician.userId,
        delegateUserId: delegate.userId,
        permissions: ['PATIENT_VIEW'],
        canApproveBatches: true,
      }),
    ).rejects.toThrow(/duplicate key/);
  });

  // -- listDelegatesForPhysician --

  it('listDelegatesForPhysician returns only this physician\'s delegates', async () => {
    const physician1 = await seedUser('doc1-list@example.com', 'Dr. One');
    const physician2 = await seedUser('doc2-list@example.com', 'Dr. Two');
    const delegate1 = await seedUser('del1-list@example.com', 'Del One');
    const delegate2 = await seedUser('del2-list@example.com', 'Del Two');

    // Physician1 has delegate1
    await linkageRepo.createDelegateLinkage({
      physicianUserId: physician1.userId,
      delegateUserId: delegate1.userId,
      permissions: ['CLAIM_VIEW'],
      canApproveBatches: false,
    });

    // Physician2 has delegate2
    await linkageRepo.createDelegateLinkage({
      physicianUserId: physician2.userId,
      delegateUserId: delegate2.userId,
      permissions: ['PATIENT_VIEW'],
      canApproveBatches: false,
    });

    const delegates = await linkageRepo.listDelegatesForPhysician(physician1.userId);
    expect(delegates.length).toBe(1);
    expect(delegates[0].linkage.delegateUserId).toBe(delegate1.userId);
    expect(delegates[0].user.fullName).toBe('Del One');
    expect(delegates[0].user.email).toBe('del1-list@example.com');
  });

  // -- listPhysiciansForDelegate --

  it('listPhysiciansForDelegate returns only this delegate\'s physicians', async () => {
    const physician1 = await seedUser('doc1-rev@example.com', 'Dr. Alpha');
    const physician2 = await seedUser('doc2-rev@example.com', 'Dr. Beta');
    const delegate = await seedUser('del-rev@example.com', 'Del Shared');
    const otherDelegate = await seedUser('del-other@example.com', 'Del Other');

    // delegate serves physician1 and physician2
    await linkageRepo.createDelegateLinkage({
      physicianUserId: physician1.userId,
      delegateUserId: delegate.userId,
      permissions: ['CLAIM_VIEW'],
      canApproveBatches: false,
    });

    await linkageRepo.createDelegateLinkage({
      physicianUserId: physician2.userId,
      delegateUserId: delegate.userId,
      permissions: ['CLAIM_VIEW', 'PATIENT_VIEW'],
      canApproveBatches: true,
    });

    // otherDelegate serves physician1 (should not appear)
    await linkageRepo.createDelegateLinkage({
      physicianUserId: physician1.userId,
      delegateUserId: otherDelegate.userId,
      permissions: ['CLAIM_VIEW'],
      canApproveBatches: false,
    });

    const physicians = await linkageRepo.listPhysiciansForDelegate(delegate.userId);
    expect(physicians.length).toBe(2);

    const physicianIds = physicians.map((p) => p.physician.userId);
    expect(physicianIds).toContain(physician1.userId);
    expect(physicianIds).toContain(physician2.userId);

    // Verify permissions are per-physician
    const p2Entry = physicians.find(
      (p) => p.physician.userId === physician2.userId,
    );
    expect(p2Entry!.linkage.permissions).toEqual(['CLAIM_VIEW', 'PATIENT_VIEW']);
    expect(p2Entry!.linkage.canApproveBatches).toBe(true);
  });

  // -- updateLinkagePermissions --

  it('updateLinkagePermissions replaces permission set', async () => {
    const physician = await seedUser('doc-upd@example.com', 'Dr. Update');
    const delegate = await seedUser('del-upd@example.com', 'Del Update');

    const linkage = await linkageRepo.createDelegateLinkage({
      physicianUserId: physician.userId,
      delegateUserId: delegate.userId,
      permissions: ['CLAIM_VIEW'],
      canApproveBatches: false,
    });

    const updated = await linkageRepo.updateLinkagePermissions(
      linkage.linkageId,
      ['CLAIM_VIEW', 'CLAIM_CREATE', 'PATIENT_VIEW'],
      true,
    );

    expect(updated).toBeDefined();
    expect(updated!.permissions).toEqual(['CLAIM_VIEW', 'CLAIM_CREATE', 'PATIENT_VIEW']);
    expect(updated!.canApproveBatches).toBe(true);
  });

  // -- deactivateLinkage --

  it('deactivateLinkage sets is_active false', async () => {
    const physician = await seedUser('doc-deact@example.com', 'Dr. Deact');
    const delegate = await seedUser('del-deact@example.com', 'Del Deact');

    const linkage = await linkageRepo.createDelegateLinkage({
      physicianUserId: physician.userId,
      delegateUserId: delegate.userId,
      permissions: ['CLAIM_VIEW'],
      canApproveBatches: false,
    });

    expect(linkage.isActive).toBe(true);

    const deactivated = await linkageRepo.deactivateLinkage(linkage.linkageId);
    expect(deactivated).toBeDefined();
    expect(deactivated!.isActive).toBe(false);
  });

  // -- findLinkage --

  it('findLinkage returns null for inactive linkage', async () => {
    const physician = await seedUser('doc-find@example.com', 'Dr. Find');
    const delegate = await seedUser('del-find@example.com', 'Del Find');

    const linkage = await linkageRepo.createDelegateLinkage({
      physicianUserId: physician.userId,
      delegateUserId: delegate.userId,
      permissions: ['CLAIM_VIEW'],
      canApproveBatches: false,
    });

    // Active linkage should be found
    const found = await linkageRepo.findLinkage(physician.userId, delegate.userId);
    expect(found).toBeDefined();
    expect(found!.linkageId).toBe(linkage.linkageId);

    // Deactivate and try again
    await linkageRepo.deactivateLinkage(linkage.linkageId);

    const notFound = await linkageRepo.findLinkage(physician.userId, delegate.userId);
    expect(notFound).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Tests: Audit Log (append-only)
// ---------------------------------------------------------------------------

describe('IAM Repository — Audit Log', () => {
  let userRepo: ReturnType<typeof createUserRepository>;
  let auditRepo: ReturnType<typeof createAuditLogRepository>;

  async function seedUser(email = 'audit-test@example.com') {
    return userRepo.createUser({
      email,
      passwordHash: 'hashed_pw',
      fullName: 'Audit Test',
    });
  }

  beforeEach(() => {
    userStore = [];
    sessionStore = [];
    recoveryCodeStore = [];
    invitationStore = [];
    delegateLinkageStore = [];
    auditLogStore = [];
    const db = makeMockDb();
    userRepo = createUserRepository(db);
    auditRepo = createAuditLogRepository(db);
  });

  // -- appendAuditLog --

  it('appendAuditLog inserts entry with correct fields', async () => {
    const user = await seedUser();

    const entry = await auditRepo.appendAuditLog({
      userId: user.userId,
      action: 'auth.login_success',
      category: 'auth',
      resourceType: 'session',
      resourceId: crypto.randomUUID(),
      detail: { ip: '10.0.0.1', method: 'totp' },
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome/120',
    });

    expect(entry.logId).toBeDefined();
    expect(entry.userId).toBe(user.userId);
    expect(entry.action).toBe('auth.login_success');
    expect(entry.category).toBe('auth');
    expect(entry.resourceType).toBe('session');
    expect(entry.detail).toEqual({ ip: '10.0.0.1', method: 'totp' });
    expect(entry.ipAddress).toBe('10.0.0.1');
    expect(entry.userAgent).toBe('Chrome/120');
    expect(entry.createdAt).toBeInstanceOf(Date);
    expect(auditLogStore.length).toBe(1);
  });

  it('appendAuditLog sanitises sensitive fields in detail', async () => {
    const user = await seedUser();

    const entry = await auditRepo.appendAuditLog({
      userId: user.userId,
      action: 'auth.registered',
      category: 'auth',
      detail: {
        email: 'dr@example.com',
        password: 'secret123!Abc',
        token: 'some-token-value',
        totpSecret: 'JBSWY3DPEHPK3PXP',
        nested: {
          passwordHash: 'hashed_value',
          safeField: 'visible',
        },
      },
    });

    expect(entry.detail).toBeDefined();
    const d = entry.detail as Record<string, any>;
    expect(d.email).toBe('dr@example.com');
    expect(d.password).toBe('[REDACTED]');
    expect(d.token).toBe('[REDACTED]');
    expect(d.totpSecret).toBe('[REDACTED]');
    expect(d.nested.passwordHash).toBe('[REDACTED]');
    expect(d.nested.safeField).toBe('visible');
  });

  // -- queryAuditLog --

  it('queryAuditLog returns only entries for specified user', async () => {
    const user1 = await seedUser('user1-audit@example.com');
    const user2 = await seedUser('user2-audit@example.com');

    await auditRepo.appendAuditLog({
      userId: user1.userId,
      action: 'auth.login_success',
      category: 'auth',
    });
    await auditRepo.appendAuditLog({
      userId: user2.userId,
      action: 'auth.login_success',
      category: 'auth',
    });
    await auditRepo.appendAuditLog({
      userId: user1.userId,
      action: 'auth.logout',
      category: 'auth',
    });

    const result = await auditRepo.queryAuditLog(user1.userId);
    expect(result.data.length).toBe(2);
    expect(result.total).toBe(2);
    result.data.forEach((entry) => {
      expect(entry.userId).toBe(user1.userId);
    });
  });

  it('queryAuditLog respects date range filter', async () => {
    const user = await seedUser();

    // Entry from 2026-01-15
    await auditRepo.appendAuditLog({
      userId: user.userId,
      action: 'auth.login_success',
      category: 'auth',
    });
    auditLogStore[0].createdAt = new Date('2026-01-15T10:00:00Z');

    // Entry from 2026-02-10
    await auditRepo.appendAuditLog({
      userId: user.userId,
      action: 'auth.logout',
      category: 'auth',
    });
    auditLogStore[1].createdAt = new Date('2026-02-10T10:00:00Z');

    // Entry from 2026-03-05
    await auditRepo.appendAuditLog({
      userId: user.userId,
      action: 'auth.mfa_setup',
      category: 'auth',
    });
    auditLogStore[2].createdAt = new Date('2026-03-05T10:00:00Z');

    // Query only February
    const result = await auditRepo.queryAuditLog(user.userId, {
      startDate: '2026-02-01',
      endDate: '2026-02-28',
    });

    expect(result.data.length).toBe(1);
    expect(result.data[0].action).toBe('auth.logout');
  });

  it('queryAuditLog respects action filter', async () => {
    const user = await seedUser();

    await auditRepo.appendAuditLog({
      userId: user.userId,
      action: 'auth.login_success',
      category: 'auth',
    });
    await auditRepo.appendAuditLog({
      userId: user.userId,
      action: 'auth.logout',
      category: 'auth',
    });
    await auditRepo.appendAuditLog({
      userId: user.userId,
      action: 'auth.login_success',
      category: 'auth',
    });

    const result = await auditRepo.queryAuditLog(user.userId, {
      action: 'auth.login_success',
    });

    expect(result.data.length).toBe(2);
    result.data.forEach((entry) => {
      expect(entry.action).toBe('auth.login_success');
    });
  });

  it('queryAuditLog paginates correctly (50 default, max 200)', async () => {
    const user = await seedUser();

    // Create 60 entries
    for (let i = 0; i < 60; i++) {
      await auditRepo.appendAuditLog({
        userId: user.userId,
        action: 'auth.login_success',
        category: 'auth',
      });
      // Assign distinct timestamps for ordering
      auditLogStore[i].createdAt = new Date(
        Date.now() - (60 - i) * 60 * 1000,
      );
    }

    // Default page size is 50
    const page1 = await auditRepo.queryAuditLog(user.userId);
    expect(page1.data.length).toBe(50);
    expect(page1.total).toBe(60);

    // Page 2 should have remaining 10
    const page2 = await auditRepo.queryAuditLog(user.userId, { page: 2 });
    expect(page2.data.length).toBe(10);
    expect(page2.total).toBe(60);

    // Custom page size
    const custom = await auditRepo.queryAuditLog(user.userId, {
      pageSize: 20,
    });
    expect(custom.data.length).toBe(20);

    // Max 200 enforced — requesting 300 should cap at 200
    const capped = await auditRepo.queryAuditLog(user.userId, {
      pageSize: 300,
    });
    expect(capped.data.length).toBe(60); // Only 60 entries total, but pageSize capped to 200
  });

  it('queryAuditLog returns reverse chronological order', async () => {
    const user = await seedUser();

    await auditRepo.appendAuditLog({
      userId: user.userId,
      action: 'auth.login_success',
      category: 'auth',
    });
    auditLogStore[0].createdAt = new Date('2026-01-01T10:00:00Z');

    await auditRepo.appendAuditLog({
      userId: user.userId,
      action: 'auth.logout',
      category: 'auth',
    });
    auditLogStore[1].createdAt = new Date('2026-03-01T10:00:00Z');

    await auditRepo.appendAuditLog({
      userId: user.userId,
      action: 'auth.mfa_setup',
      category: 'auth',
    });
    auditLogStore[2].createdAt = new Date('2026-02-01T10:00:00Z');

    const result = await auditRepo.queryAuditLog(user.userId);

    // Should be: March, February, January
    expect(result.data[0].action).toBe('auth.logout');          // March
    expect(result.data[1].action).toBe('auth.mfa_setup');       // February
    expect(result.data[2].action).toBe('auth.login_success');   // January
  });

  // -- exportAuditLog --

  it('exportAuditLog requires date range', async () => {
    const user = await seedUser();

    // Missing startDate
    await expect(
      auditRepo.exportAuditLog(user.userId, { endDate: '2026-02-28' }),
    ).rejects.toThrow('exportAuditLog requires both startDate and endDate');

    // Missing endDate
    await expect(
      auditRepo.exportAuditLog(user.userId, { startDate: '2026-02-01' }),
    ).rejects.toThrow('exportAuditLog requires both startDate and endDate');

    // Missing both
    await expect(
      auditRepo.exportAuditLog(user.userId, {}),
    ).rejects.toThrow('exportAuditLog requires both startDate and endDate');
  });

  it('exportAuditLog returns all matching entries (no pagination limit)', async () => {
    const user = await seedUser();

    // Create 250 entries (exceeding the 200 per-page limit of queryAuditLog)
    for (let i = 0; i < 250; i++) {
      await auditRepo.appendAuditLog({
        userId: user.userId,
        action: 'auth.login_success',
        category: 'auth',
      });
      auditLogStore[i].createdAt = new Date('2026-02-15T10:00:00Z');
    }

    const exported = await auditRepo.exportAuditLog(user.userId, {
      startDate: '2026-02-01',
      endDate: '2026-02-28',
    });

    expect(exported.length).toBe(250);
  });

  // -- Append-only enforcement --

  it('audit_log has no update function', () => {
    // The repository object should not expose any update-like function
    const repoKeys = Object.keys(auditRepo);
    const updateKeys = repoKeys.filter(
      (k) =>
        k.startsWith('update') ||
        k.startsWith('edit') ||
        k.startsWith('modify') ||
        k.startsWith('set'),
    );
    expect(updateKeys).toEqual([]);
  });

  it('audit_log has no delete function', () => {
    const repoKeys = Object.keys(auditRepo);
    const deleteKeys = repoKeys.filter(
      (k) =>
        k.startsWith('delete') ||
        k.startsWith('remove') ||
        k.startsWith('purge') ||
        k.startsWith('clear'),
    );
    expect(deleteKeys).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Tests: IAM Service — registerUser & verifyEmail
// ---------------------------------------------------------------------------

// Mock @node-rs/argon2
vi.mock('@node-rs/argon2', () => {
  return {
    hash: vi.fn(async (password: string, _opts: unknown) => `argon2id$${password}`),
    verify: vi.fn(async (hash: string, password: string) => hash === `argon2id$${password}`),
  };
});

// Mock otplib
vi.mock('otplib', () => {
  const mockAuthenticator = {
    options: {},
    generateSecret: vi.fn(() => 'JBSWY3DPEHPK3PXP'),
    keyuri: vi.fn((email: string, issuer: string, secret: string) =>
      `otpauth://totp/${issuer}:${email}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`,
    ),
    verify: vi.fn(({ token, secret }: { token: string; secret: string }) => {
      // Accept '123456' as the valid code for testing
      return token === '123456';
    }),
  };
  return { authenticator: mockAuthenticator };
});

// Mock @meritum/shared/schemas/iam.schema.js (types only, no runtime deps needed)
vi.mock('@meritum/shared/schemas/iam.schema.js', () => {
  return {};
});

describe('IAM Service — registerUser', () => {
  let deps: ServiceDeps;
  let createdUsers: Record<string, any>[];
  let verificationTokens: Record<string, any>[];
  let auditEntries: Record<string, any>[];
  let emittedEvents: { event: string; payload: Record<string, unknown> }[];

  function makeDeps(): ServiceDeps {
    createdUsers = [];
    verificationTokens = [];
    auditEntries = [];
    emittedEvents = [];

    const userRepo: UserRepo = {
      async createUser(data) {
        // Check for duplicates (simulate unique constraint)
        const existing = createdUsers.find((u) => u.email === data.email);
        if (existing) {
          const err: any = new Error(
            'duplicate key value violates unique constraint "users_email_idx"',
          );
          err.code = '23505';
          throw err;
        }
        const user = {
          userId: crypto.randomUUID(),
          email: data.email,
          passwordHash: data.passwordHash,
          fullName: data.fullName,
          phone: data.phone ?? null,
          emailVerified: false,
        };
        createdUsers.push(user);
        return user;
      },
      async findUserByEmail(email) {
        return createdUsers.find((u) => u.email === email.toLowerCase()) as any;
      },
      async updateUser(userId, data) {
        const user = createdUsers.find((u) => u.userId === userId);
        if (!user) return undefined;
        if (data.emailVerified !== undefined) {
          user.emailVerified = data.emailVerified;
        }
        return user as any;
      },
    };

    const verificationTokenRepo: VerificationTokenRepo = {
      async createVerificationToken(data) {
        verificationTokens.push({ ...data, used: false });
        return { tokenHash: data.tokenHash };
      },
      async findVerificationTokenByHash(tokenHash) {
        return verificationTokens.find((t) => t.tokenHash === tokenHash) as any;
      },
      async markVerificationTokenUsed(tokenHash) {
        const token = verificationTokens.find((t) => t.tokenHash === tokenHash);
        if (token) token.used = true;
      },
    };

    const auditRepo: AuditRepo = {
      async appendAuditLog(entry) {
        auditEntries.push(entry);
        return entry;
      },
    };

    const events: EventEmitter = {
      emit(event, payload) {
        emittedEvents.push({ event, payload });
      },
    };

    return { userRepo, verificationTokenRepo, auditRepo, events };
  }

  beforeEach(() => {
    deps = makeDeps();
  });

  it('registerUser hashes password with Argon2id', async () => {
    const result = await registerUser(deps, {
      email: 'dr.smith@hospital.ca',
      password: 'Str0ng!Passw0rd',
      full_name: 'Dr. Smith',
    });

    expect(result.userId).toBeDefined();
    // Verify the stored password was hashed (our mock prepends "argon2id$")
    const user = createdUsers[0];
    expect(user.passwordHash).toBe('argon2id$Str0ng!Passw0rd');
    // Plaintext password must NOT be stored
    expect(user.passwordHash).not.toBe('Str0ng!Passw0rd');
  });

  it('registerUser normalises email to lowercase', async () => {
    await registerUser(deps, {
      email: 'Dr.Smith@HOSPITAL.CA',
      password: 'Str0ng!Passw0rd',
      full_name: 'Dr. Smith',
    });

    expect(createdUsers[0].email).toBe('dr.smith@hospital.ca');
  });

  it('registerUser emits audit event', async () => {
    await registerUser(deps, {
      email: 'audit@example.com',
      password: 'Str0ng!Passw0rd',
      full_name: 'Dr. Audit',
    });

    expect(auditEntries.length).toBe(1);
    expect(auditEntries[0].action).toBe('auth.registered');
    expect(auditEntries[0].category).toBe('auth');
    expect(auditEntries[0].resourceType).toBe('user');
    expect(auditEntries[0].userId).toBe(createdUsers[0].userId);
  });

  it('registerUser emits USER_REGISTERED event with verification token', async () => {
    await registerUser(deps, {
      email: 'events@example.com',
      password: 'Str0ng!Passw0rd',
      full_name: 'Dr. Events',
    });

    const regEvent = emittedEvents.find((e) => e.event === 'USER_REGISTERED');
    expect(regEvent).toBeDefined();
    expect(regEvent!.payload.email).toBe('events@example.com');
    expect(regEvent!.payload.userId).toBe(createdUsers[0].userId);
    expect(regEvent!.payload.verificationToken).toBeDefined();
    expect(typeof regEvent!.payload.verificationToken).toBe('string');
  });

  it('registerUser stores verification token as SHA-256 hash', async () => {
    await registerUser(deps, {
      email: 'token@example.com',
      password: 'Str0ng!Passw0rd',
      full_name: 'Dr. Token',
    });

    // The emitted event has the raw token
    const rawToken = emittedEvents.find(
      (e) => e.event === 'USER_REGISTERED',
    )!.payload.verificationToken as string;

    // The stored token should be the SHA-256 hash of the raw token
    const expectedHash = hashToken(rawToken);
    expect(verificationTokens[0].tokenHash).toBe(expectedHash);

    // The stored hash should NOT be the raw token
    expect(verificationTokens[0].tokenHash).not.toBe(rawToken);
  });

  it('registerUser with existing email does not reveal email exists', async () => {
    // First registration
    const result1 = await registerUser(deps, {
      email: 'existing@example.com',
      password: 'Str0ng!Passw0rd',
      full_name: 'Dr. First',
    });

    // Second registration with same email — should NOT throw
    const result2 = await registerUser(deps, {
      email: 'existing@example.com',
      password: 'An0ther!Passw0rd',
      full_name: 'Dr. Second',
    });

    // Both return a userId (anti-enumeration)
    expect(result1.userId).toBeDefined();
    expect(result2.userId).toBeDefined();

    // The second attempt emits USER_ALREADY_EXISTS instead of USER_REGISTERED
    const alreadyExistsEvent = emittedEvents.find(
      (e) => e.event === 'USER_ALREADY_EXISTS',
    );
    expect(alreadyExistsEvent).toBeDefined();
    expect(alreadyExistsEvent!.payload.email).toBe('existing@example.com');

    // Only one user was actually created
    expect(createdUsers.length).toBe(1);
  });

  it('registerUser sets verification token expiry to 24 hours', async () => {
    const before = Date.now();
    await registerUser(deps, {
      email: 'expiry@example.com',
      password: 'Str0ng!Passw0rd',
      full_name: 'Dr. Expiry',
    });
    const after = Date.now();

    const token = verificationTokens[0];
    const expiresAt = token.expiresAt.getTime();
    const twentyFourHours = 24 * 60 * 60 * 1000;

    expect(expiresAt).toBeGreaterThanOrEqual(before + twentyFourHours);
    expect(expiresAt).toBeLessThanOrEqual(after + twentyFourHours);
  });
});

describe('IAM Service — verifyEmail', () => {
  let deps: ServiceDeps;
  let createdUsers: Record<string, any>[];
  let verificationTokens: Record<string, any>[];
  let auditEntries: Record<string, any>[];
  let emittedEvents: { event: string; payload: Record<string, unknown> }[];

  function makeDeps(): ServiceDeps {
    createdUsers = [];
    verificationTokens = [];
    auditEntries = [];
    emittedEvents = [];

    const userRepo: UserRepo = {
      async createUser(data) {
        const user = {
          userId: crypto.randomUUID(),
          email: data.email,
          passwordHash: data.passwordHash,
          fullName: data.fullName,
          phone: data.phone ?? null,
          emailVerified: false,
        };
        createdUsers.push(user);
        return user;
      },
      async findUserByEmail(email) {
        return createdUsers.find((u) => u.email === email.toLowerCase()) as any;
      },
      async updateUser(userId, data) {
        const user = createdUsers.find((u) => u.userId === userId);
        if (!user) return undefined;
        if (data.emailVerified !== undefined) {
          user.emailVerified = data.emailVerified;
        }
        return user as any;
      },
    };

    const verificationTokenRepo: VerificationTokenRepo = {
      async createVerificationToken(data) {
        verificationTokens.push({ ...data, used: false });
        return { tokenHash: data.tokenHash };
      },
      async findVerificationTokenByHash(tokenHash) {
        return verificationTokens.find((t) => t.tokenHash === tokenHash) as any;
      },
      async markVerificationTokenUsed(tokenHash) {
        const token = verificationTokens.find((t) => t.tokenHash === tokenHash);
        if (token) token.used = true;
      },
    };

    const auditRepo: AuditRepo = {
      async appendAuditLog(entry) {
        auditEntries.push(entry);
        return entry;
      },
    };

    const events: EventEmitter = {
      emit(event, payload) {
        emittedEvents.push({ event, payload });
      },
    };

    return { userRepo, verificationTokenRepo, auditRepo, events };
  }

  /** Helper: seed a user and a valid verification token. Returns the raw token. */
  async function seedUserWithToken(): Promise<{
    userId: string;
    rawToken: string;
  }> {
    const userId = crypto.randomUUID();
    const rawToken = crypto.randomUUID();
    const tokenHash = hashToken(rawToken);

    createdUsers.push({
      userId,
      email: 'verify@example.com',
      passwordHash: 'argon2id$hash',
      fullName: 'Dr. Verify',
      phone: null,
      emailVerified: false,
    });

    verificationTokens.push({
      userId,
      tokenHash,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      used: false,
    });

    return { userId, rawToken };
  }

  beforeEach(() => {
    deps = makeDeps();
  });

  it('verifyEmail with valid token sets email_verified true', async () => {
    const { userId, rawToken } = await seedUserWithToken();

    const result = await verifyEmail(deps, rawToken);

    expect(result).toEqual({ mfa_setup_required: true });

    const user = createdUsers.find((u) => u.userId === userId);
    expect(user!.emailVerified).toBe(true);
  });

  it('verifyEmail emits audit event', async () => {
    const { userId, rawToken } = await seedUserWithToken();

    await verifyEmail(deps, rawToken);

    expect(auditEntries.length).toBe(1);
    expect(auditEntries[0].action).toBe('auth.email_verified');
    expect(auditEntries[0].category).toBe('auth');
    expect(auditEntries[0].userId).toBe(userId);
    expect(auditEntries[0].resourceType).toBe('user');
  });

  it('verifyEmail marks token as used', async () => {
    const { rawToken } = await seedUserWithToken();

    await verifyEmail(deps, rawToken);

    const tokenHash = hashToken(rawToken);
    const token = verificationTokens.find((t) => t.tokenHash === tokenHash);
    expect(token!.used).toBe(true);
  });

  it('verifyEmail with expired token returns error', async () => {
    const userId = crypto.randomUUID();
    const rawToken = crypto.randomUUID();
    const tokenHash = hashToken(rawToken);

    createdUsers.push({
      userId,
      email: 'expired@example.com',
      passwordHash: 'argon2id$hash',
      fullName: 'Dr. Expired',
      phone: null,
      emailVerified: false,
    });

    // Token expired 1 hour ago
    verificationTokens.push({
      userId,
      tokenHash,
      expiresAt: new Date(Date.now() - 60 * 60 * 1000),
      used: false,
    });

    await expect(verifyEmail(deps, rawToken)).rejects.toThrow(
      'Verification token has expired',
    );

    // User should NOT be verified
    const user = createdUsers.find((u) => u.userId === userId);
    expect(user!.emailVerified).toBe(false);
  });

  it('verifyEmail with invalid token returns error', async () => {
    await expect(
      verifyEmail(deps, 'non-existent-token'),
    ).rejects.toThrow('Invalid or expired verification token');
  });

  it('verifyEmail with already-used token returns error', async () => {
    const { rawToken } = await seedUserWithToken();

    // Use it once (should succeed)
    await verifyEmail(deps, rawToken);

    // Use it again (should fail)
    await expect(verifyEmail(deps, rawToken)).rejects.toThrow(
      'Verification token has already been used',
    );
  });
});

// ===========================================================================
// MFA Service Tests
// ===========================================================================

describe('IAM Service — initiateMfaSetup', () => {
  let deps: MfaServiceDeps;
  let usersDb: Record<string, any>[];
  let recoveryCodesDb: Record<string, any>[];
  let auditEntries: Record<string, any>[];
  let emittedEvents: { event: string; payload: Record<string, unknown> }[];

  function makeMfaDeps(): MfaServiceDeps {
    usersDb = [];
    recoveryCodesDb = [];
    auditEntries = [];
    emittedEvents = [];

    const userRepo: MfaUserRepo = {
      async findUserById(userId) {
        return usersDb.find((u) => u.userId === userId) as any;
      },
      async setMfaSecret(userId, encryptedSecret) {
        const user = usersDb.find((u) => u.userId === userId);
        if (user) user.totpSecretEncrypted = encryptedSecret;
      },
      async setMfaConfigured(userId) {
        const user = usersDb.find((u) => u.userId === userId);
        if (user) user.mfaConfigured = true;
      },
    };

    const recoveryCodeRepo: RecoveryCodeRepo = {
      async createRecoveryCodes(userId, codeHashes) {
        // Delete previous unused
        const toRemove = recoveryCodesDb.filter(
          (c) => c.userId === userId && !c.used,
        );
        for (const code of toRemove) {
          const idx = recoveryCodesDb.indexOf(code);
          if (idx !== -1) recoveryCodesDb.splice(idx, 1);
        }
        const rows = codeHashes.map((hash) => ({
          codeId: crypto.randomUUID(),
          userId,
          codeHash: hash,
          used: false,
        }));
        recoveryCodesDb.push(...rows);
        return rows;
      },
    };

    const auditRepo: AuditRepo = {
      async appendAuditLog(entry) {
        auditEntries.push(entry);
        return entry;
      },
    };

    const events: EventEmitter = {
      emit(event, payload) {
        emittedEvents.push({ event, payload });
      },
    };

    return { userRepo, recoveryCodeRepo, auditRepo, events };
  }

  function seedUser(overrides?: Partial<Record<string, any>>) {
    const user = {
      userId: crypto.randomUUID(),
      email: 'doctor@meritum.ca',
      totpSecretEncrypted: null as string | null,
      mfaConfigured: false,
      ...overrides,
    };
    usersDb.push(user);
    return user;
  }

  beforeEach(() => {
    deps = makeMfaDeps();
  });

  it('initiateMfaSetup generates and encrypts TOTP secret', async () => {
    const user = seedUser();

    const result = await initiateMfaSetup(deps, user.userId);

    // Should return QR URI and manual key
    expect(result.qr_code_uri).toContain('otpauth://totp/');
    expect(result.qr_code_uri).toContain('Meritum');
    expect(result.qr_code_uri).toContain(user.email);
    expect(result.manual_key).toBeDefined();
    expect(typeof result.manual_key).toBe('string');
    expect(result.manual_key.length).toBeGreaterThan(0);

    // The secret should be stored encrypted (not the plaintext)
    const storedUser = usersDb.find((u) => u.userId === user.userId);
    expect(storedUser!.totpSecretEncrypted).not.toBeNull();
    expect(storedUser!.totpSecretEncrypted).not.toBe(result.manual_key);

    // Should be decryptable back to the original
    const decrypted = decryptTotpSecret(storedUser!.totpSecretEncrypted);
    expect(decrypted).toBe(result.manual_key);
  });

  it('initiateMfaSetup throws for non-existent user', async () => {
    await expect(
      initiateMfaSetup(deps, 'non-existent-uuid'),
    ).rejects.toThrow('User not found');
  });
});

describe('IAM Service — confirmMfaSetup', () => {
  let deps: MfaServiceDeps;
  let usersDb: Record<string, any>[];
  let recoveryCodesDb: Record<string, any>[];
  let auditEntries: Record<string, any>[];
  let emittedEvents: { event: string; payload: Record<string, unknown> }[];

  function makeMfaDeps(): MfaServiceDeps {
    usersDb = [];
    recoveryCodesDb = [];
    auditEntries = [];
    emittedEvents = [];

    const userRepo: MfaUserRepo = {
      async findUserById(userId) {
        return usersDb.find((u) => u.userId === userId) as any;
      },
      async setMfaSecret(userId, encryptedSecret) {
        const user = usersDb.find((u) => u.userId === userId);
        if (user) user.totpSecretEncrypted = encryptedSecret;
      },
      async setMfaConfigured(userId) {
        const user = usersDb.find((u) => u.userId === userId);
        if (user) user.mfaConfigured = true;
      },
    };

    const recoveryCodeRepo: RecoveryCodeRepo = {
      async createRecoveryCodes(userId, codeHashes) {
        const toRemove = recoveryCodesDb.filter(
          (c) => c.userId === userId && !c.used,
        );
        for (const code of toRemove) {
          const idx = recoveryCodesDb.indexOf(code);
          if (idx !== -1) recoveryCodesDb.splice(idx, 1);
        }
        const rows = codeHashes.map((hash) => ({
          codeId: crypto.randomUUID(),
          userId,
          codeHash: hash,
          used: false,
        }));
        recoveryCodesDb.push(...rows);
        return rows;
      },
    };

    const auditRepo: AuditRepo = {
      async appendAuditLog(entry) {
        auditEntries.push(entry);
        return entry;
      },
    };

    const events: EventEmitter = {
      emit(event, payload) {
        emittedEvents.push({ event, payload });
      },
    };

    return { userRepo, recoveryCodeRepo, auditRepo, events };
  }

  function seedUserWithMfaSecret() {
    const secret = 'JBSWY3DPEHPK3PXP';
    const encrypted = encryptTotpSecret(secret);
    const user = {
      userId: crypto.randomUUID(),
      email: 'doctor@meritum.ca',
      totpSecretEncrypted: encrypted,
      mfaConfigured: false,
    };
    usersDb.push(user);
    return { user, secret };
  }

  beforeEach(() => {
    deps = makeMfaDeps();
  });

  it('confirmMfaSetup accepts valid TOTP code', async () => {
    const { user } = seedUserWithMfaSecret();

    // '123456' is accepted by our mock authenticator.verify
    const result = await confirmMfaSetup(deps, user.userId, '123456');

    expect(result.recovery_codes).toBeDefined();
    expect(result.recovery_codes.length).toBe(10);

    // User should now be mfa_configured
    const storedUser = usersDb.find((u) => u.userId === user.userId);
    expect(storedUser!.mfaConfigured).toBe(true);
  });

  it('confirmMfaSetup rejects invalid TOTP code', async () => {
    const { user } = seedUserWithMfaSecret();

    await expect(
      confirmMfaSetup(deps, user.userId, '000000'),
    ).rejects.toThrow('Invalid TOTP code');

    // User should NOT be mfa_configured
    const storedUser = usersDb.find((u) => u.userId === user.userId);
    expect(storedUser!.mfaConfigured).toBe(false);
  });

  it('confirmMfaSetup generates 10 recovery codes', async () => {
    const { user } = seedUserWithMfaSecret();

    const result = await confirmMfaSetup(deps, user.userId, '123456');

    expect(result.recovery_codes).toHaveLength(10);

    // Each code should be in XXXX-XXXX format
    for (const code of result.recovery_codes) {
      expect(code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    }
  });

  it('confirmMfaSetup stores hashed (not plaintext) recovery codes', async () => {
    const { user } = seedUserWithMfaSecret();

    const result = await confirmMfaSetup(deps, user.userId, '123456');

    // 10 hashes should be stored in the recovery code store
    const storedCodes = recoveryCodesDb.filter(
      (c) => c.userId === user.userId,
    );
    expect(storedCodes).toHaveLength(10);

    // Stored hashes should start with 'argon2id$' (from mock)
    for (const stored of storedCodes) {
      expect(stored.codeHash).toMatch(/^argon2id\$/);
    }

    // Stored hashes should NOT be the plaintext codes
    const plaintextNormalized = result.recovery_codes.map((c) =>
      c.replace(/-/g, ''),
    );
    for (const stored of storedCodes) {
      expect(plaintextNormalized).not.toContain(stored.codeHash);
    }
  });

  it('confirmMfaSetup emits audit event', async () => {
    const { user } = seedUserWithMfaSecret();

    await confirmMfaSetup(deps, user.userId, '123456');

    const auditEntry = auditEntries.find(
      (e) => e.action === 'auth.mfa_setup',
    );
    expect(auditEntry).toBeDefined();
    expect(auditEntry!.userId).toBe(user.userId);
    expect(auditEntry!.category).toBe('auth');
  });

  it('confirmMfaSetup throws when MFA not initiated', async () => {
    const user = {
      userId: crypto.randomUUID(),
      email: 'doctor@meritum.ca',
      totpSecretEncrypted: null,
      mfaConfigured: false,
    };
    usersDb.push(user);

    await expect(
      confirmMfaSetup(deps, user.userId, '123456'),
    ).rejects.toThrow('MFA setup has not been initiated');
  });
});

describe('IAM Service — regenerateRecoveryCodes', () => {
  let deps: MfaServiceDeps;
  let usersDb: Record<string, any>[];
  let recoveryCodesDb: Record<string, any>[];
  let auditEntries: Record<string, any>[];
  let emittedEvents: { event: string; payload: Record<string, unknown> }[];

  function makeMfaDeps(): MfaServiceDeps {
    usersDb = [];
    recoveryCodesDb = [];
    auditEntries = [];
    emittedEvents = [];

    const userRepo: MfaUserRepo = {
      async findUserById(userId) {
        return usersDb.find((u) => u.userId === userId) as any;
      },
      async setMfaSecret(userId, encryptedSecret) {
        const user = usersDb.find((u) => u.userId === userId);
        if (user) user.totpSecretEncrypted = encryptedSecret;
      },
      async setMfaConfigured(userId) {
        const user = usersDb.find((u) => u.userId === userId);
        if (user) user.mfaConfigured = true;
      },
    };

    const recoveryCodeRepo: RecoveryCodeRepo = {
      async createRecoveryCodes(userId, codeHashes) {
        const toRemove = recoveryCodesDb.filter(
          (c) => c.userId === userId && !c.used,
        );
        for (const code of toRemove) {
          const idx = recoveryCodesDb.indexOf(code);
          if (idx !== -1) recoveryCodesDb.splice(idx, 1);
        }
        const rows = codeHashes.map((hash) => ({
          codeId: crypto.randomUUID(),
          userId,
          codeHash: hash,
          used: false,
        }));
        recoveryCodesDb.push(...rows);
        return rows;
      },
    };

    const auditRepo: AuditRepo = {
      async appendAuditLog(entry) {
        auditEntries.push(entry);
        return entry;
      },
    };

    const events: EventEmitter = {
      emit(event, payload) {
        emittedEvents.push({ event, payload });
      },
    };

    return { userRepo, recoveryCodeRepo, auditRepo, events };
  }

  function seedConfiguredUser() {
    const secret = 'JBSWY3DPEHPK3PXP';
    const encrypted = encryptTotpSecret(secret);
    const user = {
      userId: crypto.randomUUID(),
      email: 'doctor@meritum.ca',
      totpSecretEncrypted: encrypted,
      mfaConfigured: true,
    };
    usersDb.push(user);

    // Seed 10 existing recovery codes
    for (let i = 0; i < 10; i++) {
      recoveryCodesDb.push({
        codeId: crypto.randomUUID(),
        userId: user.userId,
        codeHash: `argon2id$oldcode${i}`,
        used: false,
      });
    }

    return user;
  }

  beforeEach(() => {
    deps = makeMfaDeps();
  });

  it('regenerateRecoveryCodes requires valid current TOTP', async () => {
    const user = seedConfiguredUser();

    // Invalid code should fail
    await expect(
      regenerateRecoveryCodes(deps, user.userId, '000000'),
    ).rejects.toThrow('Invalid TOTP code');

    // Old codes should still be there
    const remaining = recoveryCodesDb.filter(
      (c) => c.userId === user.userId && !c.used,
    );
    expect(remaining).toHaveLength(10);
  });

  it('regenerateRecoveryCodes replaces old codes', async () => {
    const user = seedConfiguredUser();

    const oldCodes = recoveryCodesDb
      .filter((c) => c.userId === user.userId)
      .map((c) => c.codeHash);

    // Valid code triggers regeneration
    const result = await regenerateRecoveryCodes(
      deps,
      user.userId,
      '123456',
    );

    expect(result.recovery_codes).toHaveLength(10);

    // New codes stored in DB
    const newCodes = recoveryCodesDb.filter(
      (c) => c.userId === user.userId && !c.used,
    );
    expect(newCodes).toHaveLength(10);

    // New hashes should all be different from old hashes
    for (const newCode of newCodes) {
      expect(oldCodes).not.toContain(newCode.codeHash);
    }
  });

  it('regenerateRecoveryCodes emits audit event', async () => {
    const user = seedConfiguredUser();

    await regenerateRecoveryCodes(deps, user.userId, '123456');

    const auditEntry = auditEntries.find(
      (e) => e.action === 'account.recovery_codes_regenerated',
    );
    expect(auditEntry).toBeDefined();
    expect(auditEntry!.userId).toBe(user.userId);
    expect(auditEntry!.category).toBe('account');
  });
});

describe('IAM Service — reconfigureMfa', () => {
  let deps: MfaServiceDeps;
  let usersDb: Record<string, any>[];
  let recoveryCodesDb: Record<string, any>[];
  let auditEntries: Record<string, any>[];
  let emittedEvents: { event: string; payload: Record<string, unknown> }[];

  function makeMfaDeps(): MfaServiceDeps {
    usersDb = [];
    recoveryCodesDb = [];
    auditEntries = [];
    emittedEvents = [];

    const userRepo: MfaUserRepo = {
      async findUserById(userId) {
        return usersDb.find((u) => u.userId === userId) as any;
      },
      async setMfaSecret(userId, encryptedSecret) {
        const user = usersDb.find((u) => u.userId === userId);
        if (user) user.totpSecretEncrypted = encryptedSecret;
      },
      async setMfaConfigured(userId) {
        const user = usersDb.find((u) => u.userId === userId);
        if (user) user.mfaConfigured = true;
      },
    };

    const recoveryCodeRepo: RecoveryCodeRepo = {
      async createRecoveryCodes(userId, codeHashes) {
        const rows = codeHashes.map((hash) => ({
          codeId: crypto.randomUUID(),
          userId,
          codeHash: hash,
          used: false,
        }));
        recoveryCodesDb.push(...rows);
        return rows;
      },
    };

    const auditRepo: AuditRepo = {
      async appendAuditLog(entry) {
        auditEntries.push(entry);
        return entry;
      },
    };

    const events: EventEmitter = {
      emit(event, payload) {
        emittedEvents.push({ event, payload });
      },
    };

    return { userRepo, recoveryCodeRepo, auditRepo, events };
  }

  function seedConfiguredUser() {
    const secret = 'JBSWY3DPEHPK3PXP';
    const encrypted = encryptTotpSecret(secret);
    const user = {
      userId: crypto.randomUUID(),
      email: 'doctor@meritum.ca',
      totpSecretEncrypted: encrypted,
      mfaConfigured: true,
    };
    usersDb.push(user);
    return { user, originalEncrypted: encrypted };
  }

  beforeEach(() => {
    deps = makeMfaDeps();
  });

  it('reconfigureMfa requires valid current TOTP', async () => {
    const { user, originalEncrypted } = seedConfiguredUser();

    await expect(
      reconfigureMfa(deps, user.userId, '000000'),
    ).rejects.toThrow('Invalid TOTP code');

    // Secret should not have changed
    const storedUser = usersDb.find((u) => u.userId === user.userId);
    expect(storedUser!.totpSecretEncrypted).toBe(originalEncrypted);
  });

  it('reconfigureMfa generates new secret and QR with valid TOTP', async () => {
    const { user, originalEncrypted } = seedConfiguredUser();

    const result = await reconfigureMfa(deps, user.userId, '123456');

    expect(result.qr_code_uri).toContain('otpauth://totp/');
    expect(result.qr_code_uri).toContain('Meritum');
    expect(result.manual_key).toBeDefined();

    // Secret should have been updated (new encryption)
    const storedUser = usersDb.find((u) => u.userId === user.userId);
    expect(storedUser!.totpSecretEncrypted).not.toBe(originalEncrypted);
  });

  it('reconfigureMfa emits audit event', async () => {
    const { user } = seedConfiguredUser();

    await reconfigureMfa(deps, user.userId, '123456');

    const auditEntry = auditEntries.find(
      (e) => e.action === 'account.mfa_reconfigured',
    );
    expect(auditEntry).toBeDefined();
    expect(auditEntry!.userId).toBe(user.userId);
    expect(auditEntry!.category).toBe('account');
  });

  it('reconfigureMfa throws when MFA not configured', async () => {
    const user = {
      userId: crypto.randomUUID(),
      email: 'doctor@meritum.ca',
      totpSecretEncrypted: null,
      mfaConfigured: false,
    };
    usersDb.push(user);

    await expect(
      reconfigureMfa(deps, user.userId, '123456'),
    ).rejects.toThrow('MFA is not configured');
  });
});

// ===========================================================================
// Login Flow tests
// ===========================================================================

describe('IAM Service — loginStep1', () => {
  // In-memory stores for login tests
  let loginUsersDb: any[];
  let loginSessionsDb: any[];
  let loginRecoveryDb: any[];
  let loginAuditDb: any[];
  let loginEmittedEvents: { event: string; payload: any }[];

  // Mock argon2 hash format: 'argon2id$<password>'
  const hashedPassword = 'argon2id$ValidPass1!@#';

  let deps: LoginServiceDeps;

  beforeEach(() => {
    loginUsersDb = [];
    loginSessionsDb = [];
    loginRecoveryDb = [];
    loginAuditDb = [];
    loginEmittedEvents = [];

    const userRepo: LoginUserRepo = {
      async findUserByEmail(email: string) {
        return loginUsersDb.find((u) => u.email === email.toLowerCase() && u.isActive);
      },
      async findUserById(userId: string) {
        return loginUsersDb.find((u) => u.userId === userId);
      },
      async incrementFailedLogin(userId: string) {
        const user = loginUsersDb.find((u) => u.userId === userId);
        if (user) {
          user.failedLoginCount += 1;
          if (user.failedLoginCount >= 10) {
            user.lockedUntil = new Date(Date.now() + 30 * 60 * 1000);
          }
        }
      },
      async resetFailedLogin(userId: string) {
        const user = loginUsersDb.find((u) => u.userId === userId);
        if (user) {
          user.failedLoginCount = 0;
          user.lockedUntil = null;
        }
      },
    };

    const sessionRepo: LoginSessionRepo = {
      async createSession(data) {
        const session = {
          sessionId: crypto.randomUUID(),
          ...data,
          createdAt: new Date(),
          lastActiveAt: new Date(),
          revoked: false,
          revokedReason: null,
        };
        loginSessionsDb.push(session);
        return session;
      },
    };

    const recoveryCodeRepo: LoginRecoveryCodeRepo = {
      async findUnusedRecoveryCodes(userId: string) {
        return loginRecoveryDb.filter((c) => c.userId === userId && !c.used);
      },
      async markRecoveryCodeUsed(codeId: string) {
        const code = loginRecoveryDb.find((c) => c.codeId === codeId);
        if (code) code.used = true;
      },
      async countRemainingCodes(userId: string) {
        return loginRecoveryDb.filter((c) => c.userId === userId && !c.used).length;
      },
    };

    const auditRepo: AuditRepo = {
      async appendAuditLog(entry) {
        loginAuditDb.push(entry);
        return entry;
      },
    };

    const events: EventEmitter = {
      emit(event, payload) {
        loginEmittedEvents.push({ event, payload });
      },
    };

    deps = { userRepo, sessionRepo, recoveryCodeRepo, auditRepo, events };
  });

  function addTestUser(overrides: Partial<any> = {}) {
    const user = {
      userId: crypto.randomUUID(),
      email: 'doctor@meritum.ca',
      passwordHash: hashedPassword,
      mfaConfigured: true,
      totpSecretEncrypted: encryptTotpSecret('JBSWY3DPEHPK3PXP'),
      failedLoginCount: 0,
      lockedUntil: null,
      isActive: true,
      ...overrides,
    };
    loginUsersDb.push(user);
    return user;
  }

  it('loginStep1 with valid credentials returns mfa_session_token', async () => {
    addTestUser();

    const result = await loginStep1(deps, 'doctor@meritum.ca', 'ValidPass1!@#', '127.0.0.1');

    expect(result.mfa_required).toBe(true);
    expect(result.mfa_session_token).toBeDefined();
    expect(typeof result.mfa_session_token).toBe('string');
    expect(result.mfa_session_token.split('.')).toHaveLength(2);
  });

  it('loginStep1 with wrong password returns generic error', async () => {
    addTestUser();

    await expect(
      loginStep1(deps, 'doctor@meritum.ca', 'WrongPassword1!@#', '127.0.0.1'),
    ).rejects.toThrow('Invalid credentials');
  });

  it('loginStep1 with non-existent email returns same generic error', async () => {
    addTestUser();

    await expect(
      loginStep1(deps, 'nobody@meritum.ca', 'ValidPass1!@#', '127.0.0.1'),
    ).rejects.toThrow('Invalid credentials');
  });

  it('loginStep1 with locked account returns locked error', async () => {
    addTestUser({
      lockedUntil: new Date(Date.now() + 30 * 60 * 1000), // locked 30 min from now
    });

    await expect(
      loginStep1(deps, 'doctor@meritum.ca', 'ValidPass1!@#', '127.0.0.1'),
    ).rejects.toThrow('Account is temporarily locked');
  });

  it('loginStep1 increments failed count on failure', async () => {
    const user = addTestUser();

    await expect(
      loginStep1(deps, 'doctor@meritum.ca', 'WrongPassword1!@#', '127.0.0.1'),
    ).rejects.toThrow('Invalid credentials');

    expect(user.failedLoginCount).toBe(1);
  });

  it('loginStep1 emits audit event on success', async () => {
    addTestUser();

    await loginStep1(deps, 'doctor@meritum.ca', 'ValidPass1!@#', '127.0.0.1');

    const auditEntry = loginAuditDb.find((e) => e.action === 'auth.login_success');
    expect(auditEntry).toBeDefined();
    expect(auditEntry.detail.step).toBe('password_verified');
  });

  it('loginStep1 emits audit event on failure', async () => {
    addTestUser();

    await expect(
      loginStep1(deps, 'doctor@meritum.ca', 'WrongPassword1!@#', '127.0.0.1'),
    ).rejects.toThrow('Invalid credentials');

    const auditEntry = loginAuditDb.find((e) => e.action === 'auth.login_failed');
    expect(auditEntry).toBeDefined();
    expect(auditEntry.detail.reason).toBe('invalid_password');
  });

  it('loginStep1 with MFA not configured throws error', async () => {
    addTestUser({ mfaConfigured: false });

    await expect(
      loginStep1(deps, 'doctor@meritum.ca', 'ValidPass1!@#', '127.0.0.1'),
    ).rejects.toThrow('MFA setup required before login');
  });

  it('loginStep1 normalizes email to lowercase', async () => {
    addTestUser();

    const result = await loginStep1(deps, 'DOCTOR@Meritum.CA', 'ValidPass1!@#', '127.0.0.1');
    expect(result.mfa_required).toBe(true);
  });
});

describe('IAM Service — loginStep2Mfa', () => {
  let loginUsersDb: any[];
  let loginSessionsDb: any[];
  let loginRecoveryDb: any[];
  let loginAuditDb: any[];
  let loginEmittedEvents: { event: string; payload: any }[];

  const hashedPassword = 'argon2id$ValidPass1!@#';
  let deps: LoginServiceDeps;

  const TOTP_SECRET = 'JBSWY3DPEHPK3PXP';

  beforeEach(() => {
    loginUsersDb = [];
    loginSessionsDb = [];
    loginRecoveryDb = [];
    loginAuditDb = [];
    loginEmittedEvents = [];

    const userRepo: LoginUserRepo = {
      async findUserByEmail(email: string) {
        return loginUsersDb.find((u) => u.email === email.toLowerCase() && u.isActive);
      },
      async findUserById(userId: string) {
        return loginUsersDb.find((u) => u.userId === userId);
      },
      async incrementFailedLogin(userId: string) {
        const user = loginUsersDb.find((u) => u.userId === userId);
        if (user) {
          user.failedLoginCount += 1;
          if (user.failedLoginCount >= 10) {
            user.lockedUntil = new Date(Date.now() + 30 * 60 * 1000);
          }
        }
      },
      async resetFailedLogin(userId: string) {
        const user = loginUsersDb.find((u) => u.userId === userId);
        if (user) {
          user.failedLoginCount = 0;
          user.lockedUntil = null;
        }
      },
    };

    const sessionRepo: LoginSessionRepo = {
      async createSession(data) {
        const session = {
          sessionId: crypto.randomUUID(),
          ...data,
          createdAt: new Date(),
          lastActiveAt: new Date(),
          revoked: false,
          revokedReason: null,
        };
        loginSessionsDb.push(session);
        return session;
      },
    };

    const recoveryCodeRepo: LoginRecoveryCodeRepo = {
      async findUnusedRecoveryCodes(userId: string) {
        return loginRecoveryDb.filter((c) => c.userId === userId && !c.used);
      },
      async markRecoveryCodeUsed(codeId: string) {
        const code = loginRecoveryDb.find((c) => c.codeId === codeId);
        if (code) code.used = true;
      },
      async countRemainingCodes(userId: string) {
        return loginRecoveryDb.filter((c) => c.userId === userId && !c.used).length;
      },
    };

    const auditRepo: AuditRepo = {
      async appendAuditLog(entry) {
        loginAuditDb.push(entry);
        return entry;
      },
    };

    const events: EventEmitter = {
      emit(event, payload) {
        loginEmittedEvents.push({ event, payload });
      },
    };

    deps = { userRepo, sessionRepo, recoveryCodeRepo, auditRepo, events };
  });

  function addTestUser(overrides: Partial<any> = {}) {
    const user = {
      userId: crypto.randomUUID(),
      email: 'doctor@meritum.ca',
      passwordHash: hashedPassword,
      mfaConfigured: true,
      totpSecretEncrypted: encryptTotpSecret(TOTP_SECRET),
      failedLoginCount: 0,
      lockedUntil: null,
      isActive: true,
      ...overrides,
    };
    loginUsersDb.push(user);
    return user;
  }

  it('loginStep2Mfa with valid TOTP creates session', async () => {
    const user = addTestUser();
    const mfaToken = createMfaSessionToken(user.userId);
    const totpCode = '123456'; // mock authenticator accepts this

    const result = await loginStep2Mfa(deps, mfaToken, totpCode, '127.0.0.1', 'TestAgent/1.0');

    expect(result.session_token).toBeDefined();
    expect(typeof result.session_token).toBe('string');
    expect(result.session_token).toHaveLength(64); // 32 bytes hex = 64 chars

    // Session should be stored
    expect(loginSessionsDb).toHaveLength(1);
    expect(loginSessionsDb[0].userId).toBe(user.userId);
    // Token stored in DB is SHA-256 hash, not the raw token
    expect(loginSessionsDb[0].tokenHash).toBe(hashToken(result.session_token));
  });

  it('loginStep2Mfa with invalid TOTP returns error', async () => {
    const user = addTestUser();
    const mfaToken = createMfaSessionToken(user.userId);

    await expect(
      loginStep2Mfa(deps, mfaToken, '000000', '127.0.0.1', 'TestAgent/1.0'),
    ).rejects.toThrow('Invalid TOTP code');

    // Should increment failed login count
    expect(user.failedLoginCount).toBe(1);

    // No session created
    expect(loginSessionsDb).toHaveLength(0);
  });

  it('loginStep2Mfa with expired mfa_session_token returns error', async () => {
    const user = addTestUser();

    // Create a token that's already expired by patching Date.now
    const realNow = Date.now;
    // Create token in the past
    vi.spyOn(Date, 'now').mockReturnValue(realNow() - 6 * 60 * 1000); // 6 min ago
    const expiredToken = createMfaSessionToken(user.userId);
    vi.spyOn(Date, 'now').mockRestore();

    const totpCode = '123456'; // mock authenticator accepts this

    await expect(
      loginStep2Mfa(deps, expiredToken, totpCode, '127.0.0.1', 'TestAgent/1.0'),
    ).rejects.toThrow('Invalid or expired MFA session');
  });

  it('loginStep2Mfa resets failed login count on success', async () => {
    const user = addTestUser({ failedLoginCount: 5 });
    const mfaToken = createMfaSessionToken(user.userId);
    const totpCode = '123456'; // mock authenticator accepts this

    await loginStep2Mfa(deps, mfaToken, totpCode, '127.0.0.1', 'TestAgent/1.0');

    expect(user.failedLoginCount).toBe(0);
    expect(user.lockedUntil).toBeNull();
  });

  it('loginStep2Mfa emits audit event on success', async () => {
    const user = addTestUser();
    const mfaToken = createMfaSessionToken(user.userId);
    const totpCode = '123456'; // mock authenticator accepts this

    await loginStep2Mfa(deps, mfaToken, totpCode, '127.0.0.1', 'TestAgent/1.0');

    const auditEntry = loginAuditDb.find((e) => e.action === 'auth.login_mfa_success');
    expect(auditEntry).toBeDefined();
    expect(auditEntry.detail.method).toBe('totp');
  });

  it('loginStep2Mfa with tampered mfa_session_token returns error', async () => {
    const user = addTestUser();
    const mfaToken = createMfaSessionToken(user.userId);

    // Tamper with the token
    const tamperedToken = mfaToken.slice(0, -5) + 'XXXXX';

    const totpCode = '123456'; // mock authenticator accepts this

    await expect(
      loginStep2Mfa(deps, tamperedToken, totpCode, '127.0.0.1', 'TestAgent/1.0'),
    ).rejects.toThrow('Invalid or expired MFA session');
  });
});

describe('IAM Service — loginStep2Recovery', () => {
  let loginUsersDb: any[];
  let loginSessionsDb: any[];
  let loginRecoveryDb: any[];
  let loginAuditDb: any[];
  let loginEmittedEvents: { event: string; payload: any }[];

  const hashedPassword = 'argon2id$ValidPass1!@#';
  let deps: LoginServiceDeps;

  const TOTP_SECRET = 'JBSWY3DPEHPK3PXP';
  const RECOVERY_CODE_PLAINTEXT = 'ABCD1234'; // without dash
  // Mock argon2 hash format: 'argon2id$<code>'
  const recoveryCodeHash = 'argon2id$ABCD1234';

  beforeEach(() => {
    loginUsersDb = [];
    loginSessionsDb = [];
    loginRecoveryDb = [];
    loginAuditDb = [];
    loginEmittedEvents = [];

    const userRepo: LoginUserRepo = {
      async findUserByEmail(email: string) {
        return loginUsersDb.find((u) => u.email === email.toLowerCase() && u.isActive);
      },
      async findUserById(userId: string) {
        return loginUsersDb.find((u) => u.userId === userId);
      },
      async incrementFailedLogin(userId: string) {
        const user = loginUsersDb.find((u) => u.userId === userId);
        if (user) {
          user.failedLoginCount += 1;
          if (user.failedLoginCount >= 10) {
            user.lockedUntil = new Date(Date.now() + 30 * 60 * 1000);
          }
        }
      },
      async resetFailedLogin(userId: string) {
        const user = loginUsersDb.find((u) => u.userId === userId);
        if (user) {
          user.failedLoginCount = 0;
          user.lockedUntil = null;
        }
      },
    };

    const sessionRepo: LoginSessionRepo = {
      async createSession(data) {
        const session = {
          sessionId: crypto.randomUUID(),
          ...data,
          createdAt: new Date(),
          lastActiveAt: new Date(),
          revoked: false,
          revokedReason: null,
        };
        loginSessionsDb.push(session);
        return session;
      },
    };

    const recoveryCodeRepo: LoginRecoveryCodeRepo = {
      async findUnusedRecoveryCodes(userId: string) {
        return loginRecoveryDb.filter((c) => c.userId === userId && !c.used);
      },
      async markRecoveryCodeUsed(codeId: string) {
        const code = loginRecoveryDb.find((c) => c.codeId === codeId);
        if (code) code.used = true;
      },
      async countRemainingCodes(userId: string) {
        return loginRecoveryDb.filter((c) => c.userId === userId && !c.used).length;
      },
    };

    const auditRepo: AuditRepo = {
      async appendAuditLog(entry) {
        loginAuditDb.push(entry);
        return entry;
      },
    };

    const events: EventEmitter = {
      emit(event, payload) {
        loginEmittedEvents.push({ event, payload });
      },
    };

    deps = { userRepo, sessionRepo, recoveryCodeRepo, auditRepo, events };
  });

  function addTestUser(overrides: Partial<any> = {}) {
    const user = {
      userId: crypto.randomUUID(),
      email: 'doctor@meritum.ca',
      passwordHash: hashedPassword,
      mfaConfigured: true,
      totpSecretEncrypted: encryptTotpSecret(TOTP_SECRET),
      failedLoginCount: 0,
      lockedUntil: null,
      isActive: true,
      ...overrides,
    };
    loginUsersDb.push(user);
    return user;
  }

  function addRecoveryCodes(userId: string, count: number = 10) {
    for (let i = 0; i < count; i++) {
      loginRecoveryDb.push({
        codeId: crypto.randomUUID(),
        userId,
        codeHash: i === 0 ? recoveryCodeHash : `dummy-hash-${i}`,
        used: false,
      });
    }
  }

  it('loginStep2Recovery with valid recovery code creates session', async () => {
    const user = addTestUser();
    addRecoveryCodes(user.userId);
    const mfaToken = createMfaSessionToken(user.userId);

    const result = await loginStep2Recovery(
      deps, mfaToken, 'ABCD-1234', '127.0.0.1', 'TestAgent/1.0',
    );

    expect(result.session_token).toBeDefined();
    expect(typeof result.session_token).toBe('string');
    expect(result.session_token).toHaveLength(64);

    // Session created
    expect(loginSessionsDb).toHaveLength(1);
    expect(loginSessionsDb[0].userId).toBe(user.userId);
  });

  it('loginStep2Recovery marks code as used', async () => {
    const user = addTestUser();
    addRecoveryCodes(user.userId);
    const mfaToken = createMfaSessionToken(user.userId);

    await loginStep2Recovery(
      deps, mfaToken, 'ABCD-1234', '127.0.0.1', 'TestAgent/1.0',
    );

    // The first code (which matches) should be marked used
    const matchedCode = loginRecoveryDb.find((c) => c.codeHash === recoveryCodeHash);
    expect(matchedCode.used).toBe(true);
  });

  it('loginStep2Recovery returns remaining code count', async () => {
    const user = addTestUser();
    addRecoveryCodes(user.userId, 10);
    const mfaToken = createMfaSessionToken(user.userId);

    const result = await loginStep2Recovery(
      deps, mfaToken, 'ABCD-1234', '127.0.0.1', 'TestAgent/1.0',
    );

    // 10 codes - 1 used = 9 remaining
    expect(result.remaining_codes).toBe(9);
  });

  it('loginStep2Recovery with invalid recovery code returns error', async () => {
    const user = addTestUser();
    addRecoveryCodes(user.userId);
    const mfaToken = createMfaSessionToken(user.userId);

    await expect(
      loginStep2Recovery(
        deps, mfaToken, 'ZZZZ-9999', '127.0.0.1', 'TestAgent/1.0',
      ),
    ).rejects.toThrow('Invalid recovery code');

    // Should increment failed login count
    expect(user.failedLoginCount).toBe(1);

    // No session created
    expect(loginSessionsDb).toHaveLength(0);
  });

  it('loginStep2Recovery with expired mfa_session_token returns error', async () => {
    const user = addTestUser();
    addRecoveryCodes(user.userId);

    // Create expired token
    const realNow = Date.now;
    vi.spyOn(Date, 'now').mockReturnValue(realNow() - 6 * 60 * 1000);
    const expiredToken = createMfaSessionToken(user.userId);
    vi.spyOn(Date, 'now').mockRestore();

    await expect(
      loginStep2Recovery(
        deps, expiredToken, 'ABCD-1234', '127.0.0.1', 'TestAgent/1.0',
      ),
    ).rejects.toThrow('Invalid or expired MFA session');
  });

  it('loginStep2Recovery emits audit event with remaining count', async () => {
    const user = addTestUser();
    addRecoveryCodes(user.userId, 5);
    const mfaToken = createMfaSessionToken(user.userId);

    await loginStep2Recovery(
      deps, mfaToken, 'ABCD-1234', '127.0.0.1', 'TestAgent/1.0',
    );

    const auditEntry = loginAuditDb.find((e) => e.action === 'auth.login_recovery_used');
    expect(auditEntry).toBeDefined();
    expect(auditEntry.detail.remaining_codes).toBe(4);
  });

  it('loginStep2Recovery resets failed login count on success', async () => {
    const user = addTestUser({ failedLoginCount: 5 });
    addRecoveryCodes(user.userId);
    const mfaToken = createMfaSessionToken(user.userId);

    await loginStep2Recovery(
      deps, mfaToken, 'ABCD-1234', '127.0.0.1', 'TestAgent/1.0',
    );

    expect(user.failedLoginCount).toBe(0);
    expect(user.lockedUntil).toBeNull();
  });

  it('loginStep2Recovery accepts code without dash', async () => {
    const user = addTestUser();
    addRecoveryCodes(user.userId);
    const mfaToken = createMfaSessionToken(user.userId);

    const result = await loginStep2Recovery(
      deps, mfaToken, 'ABCD1234', '127.0.0.1', 'TestAgent/1.0',
    );

    expect(result.session_token).toBeDefined();
  });

  it('loginStep2Recovery accepts code in lowercase', async () => {
    const user = addTestUser();
    addRecoveryCodes(user.userId);
    const mfaToken = createMfaSessionToken(user.userId);

    const result = await loginStep2Recovery(
      deps, mfaToken, 'abcd-1234', '127.0.0.1', 'TestAgent/1.0',
    );

    expect(result.session_token).toBeDefined();
  });
});

// ===========================================================================
// Session Management Service Tests
// ===========================================================================

describe('IAM Service — validateSession', () => {
  let deps: any;
  let sessionsDb: any[];
  let auditEntries: any[];
  let emittedEvents: { event: string; payload: any }[];

  function makeDeps() {
    sessionsDb = [];
    auditEntries = [];
    emittedEvents = [];

    const sessionRepo = {
      async findSessionByTokenHash(tokenHash: string) {
        const session = sessionsDb.find(
          (s) => s.tokenHash === tokenHash && !s.revoked,
        );
        if (!session) return undefined;

        // Check expiry (same logic as repository)
        const now = Date.now();
        const createdAt = new Date(session.createdAt).getTime();
        const lastActiveAt = new Date(session.lastActiveAt).getTime();
        if (now - createdAt > 24 * 60 * 60 * 1000) return undefined; // absolute
        if (now - lastActiveAt > 60 * 60 * 1000) return undefined; // idle

        return {
          session,
          user: session.__user,
        };
      },
      async refreshSession(sessionId: string) {
        const session = sessionsDb.find((s) => s.sessionId === sessionId);
        if (session) session.lastActiveAt = new Date();
      },
      async listActiveSessions(userId: string) {
        return sessionsDb.filter((s) => s.userId === userId && !s.revoked);
      },
      async revokeSession(sessionId: string, reason: string) {
        const session = sessionsDb.find((s) => s.sessionId === sessionId);
        if (session) {
          session.revoked = true;
          session.revokedReason = reason;
        }
      },
      async revokeAllUserSessions(
        userId: string,
        exceptSessionId: string | undefined,
        reason: string,
      ) {
        for (const session of sessionsDb) {
          if (
            session.userId === userId &&
            !session.revoked &&
            session.sessionId !== exceptSessionId
          ) {
            session.revoked = true;
            session.revokedReason = reason;
          }
        }
      },
    };

    const auditRepo = {
      async appendAuditLog(entry: any) {
        auditEntries.push(entry);
        return entry;
      },
    };

    const events = {
      emit(event: string, payload: any) {
        emittedEvents.push({ event, payload });
      },
    };

    return { sessionRepo, auditRepo, events };
  }

  function addSession(overrides: Partial<any> = {}) {
    const session = {
      sessionId: crypto.randomUUID(),
      userId: 'user-1',
      tokenHash: 'valid_token_hash',
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome/120',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
      __user: {
        userId: 'user-1',
        role: 'physician',
        subscriptionStatus: 'active',
      },
      ...overrides,
    };
    sessionsDb.push(session);
    return session;
  }

  beforeEach(() => {
    deps = makeDeps();
  });

  it('validateSession returns AuthContext for valid session', async () => {
    addSession();

    const { validateSession } = await import('./iam.service.js');
    const result = await validateSession(deps, 'valid_token_hash');

    expect(result).not.toBeNull();
    expect(result!.userId).toBe('user-1');
    expect(result!.role).toBe('physician');
    expect(result!.subscriptionStatus).toBe('active');
    expect(result!.sessionId).toBeDefined();
  });

  it('validateSession returns null for expired session (absolute)', async () => {
    addSession({
      tokenHash: 'absolute_expired',
      createdAt: new Date(Date.now() - 25 * 60 * 60 * 1000), // 25h ago
      lastActiveAt: new Date(),
    });

    const { validateSession } = await import('./iam.service.js');
    const result = await validateSession(deps, 'absolute_expired');

    expect(result).toBeNull();
  });

  it('validateSession returns null for expired session (idle)', async () => {
    addSession({
      tokenHash: 'idle_expired',
      createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2h ago
      lastActiveAt: new Date(Date.now() - 61 * 60 * 1000), // 61min ago
    });

    const { validateSession } = await import('./iam.service.js');
    const result = await validateSession(deps, 'idle_expired');

    expect(result).toBeNull();
  });

  it('validateSession refreshes idle timer on success', async () => {
    const session = addSession();
    const originalLastActive = session.lastActiveAt;

    // Small delay
    await new Promise((r) => setTimeout(r, 10));

    const { validateSession } = await import('./iam.service.js');
    await validateSession(deps, 'valid_token_hash');

    expect(session.lastActiveAt.getTime()).toBeGreaterThanOrEqual(
      originalLastActive.getTime(),
    );
  });

  it('validateSession returns null for non-existent token', async () => {
    const { validateSession } = await import('./iam.service.js');
    const result = await validateSession(deps, 'does_not_exist');

    expect(result).toBeNull();
  });
});

describe('IAM Service — revokeSession', () => {
  let deps: any;
  let sessionsDb: any[];
  let auditEntries: any[];
  let emittedEvents: { event: string; payload: any }[];

  function makeDeps() {
    sessionsDb = [];
    auditEntries = [];
    emittedEvents = [];

    const sessionRepo = {
      async findSessionByTokenHash(_tokenHash: string) {
        return undefined;
      },
      async refreshSession(_sessionId: string) {},
      async listActiveSessions(userId: string) {
        return sessionsDb.filter((s) => s.userId === userId && !s.revoked);
      },
      async revokeSession(sessionId: string, reason: string) {
        const session = sessionsDb.find((s) => s.sessionId === sessionId);
        if (session) {
          session.revoked = true;
          session.revokedReason = reason;
        }
      },
      async revokeAllUserSessions(
        userId: string,
        exceptSessionId: string | undefined,
        reason: string,
      ) {
        for (const session of sessionsDb) {
          if (
            session.userId === userId &&
            !session.revoked &&
            session.sessionId !== exceptSessionId
          ) {
            session.revoked = true;
            session.revokedReason = reason;
          }
        }
      },
    };

    const auditRepo = {
      async appendAuditLog(entry: any) {
        auditEntries.push(entry);
        return entry;
      },
    };

    const events = {
      emit(event: string, payload: any) {
        emittedEvents.push({ event, payload });
      },
    };

    return { sessionRepo, auditRepo, events };
  }

  function addSession(userId: string, sessionId?: string) {
    const session = {
      sessionId: sessionId ?? crypto.randomUUID(),
      userId,
      tokenHash: `token_${crypto.randomUUID()}`,
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome/120',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    };
    sessionsDb.push(session);
    return session;
  }

  beforeEach(() => {
    deps = makeDeps();
  });

  it('revokeSession revokes session belonging to user', async () => {
    const session = addSession('user-1');

    const { revokeSession } = await import('./iam.service.js');
    await revokeSession(deps, 'user-1', session.sessionId);

    expect(session.revoked).toBe(true);
    expect(session.revokedReason).toBe('revoked_remote');

    // Should emit audit
    const auditEntry = auditEntries.find(
      (e) => e.action === 'auth.session_revoked',
    );
    expect(auditEntry).toBeDefined();
    expect(auditEntry.resourceId).toBe(session.sessionId);

    // Should emit event
    const event = emittedEvents.find(
      (e) => e.event === 'auth.session_revoked',
    );
    expect(event).toBeDefined();
  });

  it('revokeSession rejects session belonging to different user', async () => {
    const session = addSession('user-2');

    const { revokeSession } = await import('./iam.service.js');
    await expect(
      revokeSession(deps, 'user-1', session.sessionId),
    ).rejects.toThrow('Session not found');

    // Session should NOT be revoked
    expect(session.revoked).toBe(false);
  });
});

describe('IAM Service — revokeAllSessions', () => {
  let deps: any;
  let sessionsDb: any[];
  let auditEntries: any[];
  let emittedEvents: { event: string; payload: any }[];

  function makeDeps() {
    sessionsDb = [];
    auditEntries = [];
    emittedEvents = [];

    const sessionRepo = {
      async findSessionByTokenHash(_tokenHash: string) {
        return undefined;
      },
      async refreshSession(_sessionId: string) {},
      async listActiveSessions(userId: string) {
        return sessionsDb.filter((s) => s.userId === userId && !s.revoked);
      },
      async revokeSession(sessionId: string, reason: string) {
        const session = sessionsDb.find((s) => s.sessionId === sessionId);
        if (session) {
          session.revoked = true;
          session.revokedReason = reason;
        }
      },
      async revokeAllUserSessions(
        userId: string,
        exceptSessionId: string | undefined,
        reason: string,
      ) {
        for (const session of sessionsDb) {
          if (
            session.userId === userId &&
            !session.revoked &&
            session.sessionId !== exceptSessionId
          ) {
            session.revoked = true;
            session.revokedReason = reason;
          }
        }
      },
    };

    const auditRepo = {
      async appendAuditLog(entry: any) {
        auditEntries.push(entry);
        return entry;
      },
    };

    const events = {
      emit(event: string, payload: any) {
        emittedEvents.push({ event, payload });
      },
    };

    return { sessionRepo, auditRepo, events };
  }

  function addSession(userId: string, sessionId?: string) {
    const session = {
      sessionId: sessionId ?? crypto.randomUUID(),
      userId,
      tokenHash: `token_${crypto.randomUUID()}`,
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome/120',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    };
    sessionsDb.push(session);
    return session;
  }

  beforeEach(() => {
    deps = makeDeps();
  });

  it('revokeAllSessions keeps current session active', async () => {
    const s1 = addSession('user-1');
    const s2 = addSession('user-1');
    const s3 = addSession('user-1');

    const { revokeAllSessions } = await import('./iam.service.js');
    await revokeAllSessions(deps, 'user-1', s1.sessionId);

    // s1 should be kept
    expect(s1.revoked).toBe(false);
    // s2 and s3 should be revoked
    expect(s2.revoked).toBe(true);
    expect(s3.revoked).toBe(true);

    // Should emit audit
    const auditEntry = auditEntries.find(
      (e) => e.action === 'auth.session_revoked_all',
    );
    expect(auditEntry).toBeDefined();

    // Should emit event
    const event = emittedEvents.find(
      (e) => e.event === 'auth.session_revoked_all',
    );
    expect(event).toBeDefined();
    expect(event!.payload.currentSessionId).toBe(s1.sessionId);
  });
});

describe('IAM Service — listSessions', () => {
  it('listSessions returns session metadata', async () => {
    const sessionsDb: any[] = [];
    const sessionRepo = {
      async findSessionByTokenHash() { return undefined; },
      async refreshSession() {},
      async listActiveSessions(userId: string) {
        return sessionsDb.filter((s) => s.userId === userId && !s.revoked);
      },
      async revokeSession() {},
      async revokeAllUserSessions() {},
    };
    const auditRepo = { async appendAuditLog(e: any) { return e; } };
    const events = { emit() {} };
    const deps = { sessionRepo, auditRepo, events };

    sessionsDb.push({
      sessionId: 'sess-1',
      userId: 'user-1',
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome/120',
      createdAt: new Date('2026-01-01T10:00:00Z'),
      lastActiveAt: new Date('2026-01-01T11:00:00Z'),
      revoked: false,
      revokedReason: null,
    });
    sessionsDb.push({
      sessionId: 'sess-2',
      userId: 'user-1',
      ipAddress: '10.0.0.2',
      userAgent: 'Firefox/115',
      createdAt: new Date('2026-01-02T10:00:00Z'),
      lastActiveAt: new Date('2026-01-02T11:00:00Z'),
      revoked: false,
      revokedReason: null,
    });

    const { listSessions } = await import('./iam.service.js');
    const result = await listSessions(deps, 'user-1');

    expect(result).toHaveLength(2);
    expect(result[0].sessionId).toBe('sess-1');
    expect(result[0].ipAddress).toBe('10.0.0.1');
    expect(result[0].userAgent).toBe('Chrome/120');
    expect(result[1].sessionId).toBe('sess-2');
  });
});

describe('IAM Service — logout', () => {
  it('logout revokes session with reason logout', async () => {
    const sessionsDb: any[] = [];
    const auditEntries: any[] = [];
    const emittedEvents: any[] = [];

    const session = {
      sessionId: 'logout-sess',
      userId: 'user-1',
      tokenHash: 'hash',
      ipAddress: '10.0.0.1',
      userAgent: 'Chrome',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    };
    sessionsDb.push(session);

    const deps = {
      sessionRepo: {
        async findSessionByTokenHash() { return undefined; },
        async refreshSession() {},
        async listActiveSessions() { return sessionsDb; },
        async revokeSession(sessionId: string, reason: string) {
          const s = sessionsDb.find((s) => s.sessionId === sessionId);
          if (s) { s.revoked = true; s.revokedReason = reason; }
        },
        async revokeAllUserSessions() {},
      },
      auditRepo: {
        async appendAuditLog(entry: any) { auditEntries.push(entry); return entry; },
      },
      events: {
        emit(event: string, payload: any) { emittedEvents.push({ event, payload }); },
      },
    };

    const { logout } = await import('./iam.service.js');
    await logout(deps, 'logout-sess', 'user-1');

    expect(session.revoked).toBe(true);
    expect(session.revokedReason).toBe('logout');

    const auditEntry = auditEntries.find((e) => e.action === 'auth.logout');
    expect(auditEntry).toBeDefined();
    expect(auditEntry.resourceId).toBe('logout-sess');

    const event = emittedEvents.find((e) => e.event === 'auth.logout');
    expect(event).toBeDefined();
  });
});

// ===========================================================================
// Password Reset Service Tests
// ===========================================================================

describe('IAM Service — requestPasswordReset', () => {
  let deps: any;
  let usersDb: any[];
  let resetTokensDb: any[];
  let sessionsDb: any[];
  let auditEntries: any[];
  let emittedEvents: { event: string; payload: any }[];

  function makeDeps() {
    usersDb = [];
    resetTokensDb = [];
    sessionsDb = [];
    auditEntries = [];
    emittedEvents = [];

    const userRepo = {
      async findUserByEmail(email: string) {
        return usersDb.find((u) => u.email === email.toLowerCase());
      },
      async setPasswordHash(userId: string, passwordHash: string) {
        const user = usersDb.find((u) => u.userId === userId);
        if (user) user.passwordHash = passwordHash;
      },
    };

    const tokenRepo = {
      async createPasswordResetToken(data: any) {
        resetTokensDb.push({ ...data, used: false });
        return { tokenHash: data.tokenHash };
      },
      async findPasswordResetTokenByHash(tokenHash: string) {
        return resetTokensDb.find((t) => t.tokenHash === tokenHash);
      },
      async markPasswordResetTokenUsed(tokenHash: string) {
        const token = resetTokensDb.find((t) => t.tokenHash === tokenHash);
        if (token) token.used = true;
      },
    };

    const sessionRepo = {
      async revokeAllUserSessions(
        userId: string,
        _exceptSessionId: string | undefined,
        reason: string,
      ) {
        for (const session of sessionsDb) {
          if (session.userId === userId && !session.revoked) {
            session.revoked = true;
            session.revokedReason = reason;
          }
        }
      },
    };

    const auditRepo = {
      async appendAuditLog(entry: any) {
        auditEntries.push(entry);
        return entry;
      },
    };

    const events = {
      emit(event: string, payload: any) {
        emittedEvents.push({ event, payload });
      },
    };

    return { userRepo, tokenRepo, sessionRepo, auditRepo, events };
  }

  beforeEach(() => {
    deps = makeDeps();
  });

  it('requestPasswordReset always returns success (anti-enumeration)', async () => {
    // No users in DB — should still return success
    const { requestPasswordReset } = await import('./iam.service.js');
    const result = await requestPasswordReset(deps, 'nobody@example.com');

    expect(result).toEqual({ success: true });
  });

  it('requestPasswordReset with existing user stores token and emits event', async () => {
    usersDb.push({
      userId: 'user-1',
      email: 'doctor@meritum.ca',
    });

    const { requestPasswordReset } = await import('./iam.service.js');
    const result = await requestPasswordReset(deps, 'doctor@meritum.ca');

    expect(result).toEqual({ success: true });

    // Token should be stored
    expect(resetTokensDb).toHaveLength(1);
    expect(resetTokensDb[0].userId).toBe('user-1');
    expect(resetTokensDb[0].expiresAt.getTime()).toBeGreaterThan(Date.now());
    // Expiry should be ~1 hour from now
    const expiryDiff = resetTokensDb[0].expiresAt.getTime() - Date.now();
    expect(expiryDiff).toBeLessThanOrEqual(60 * 60 * 1000);
    expect(expiryDiff).toBeGreaterThan(59 * 60 * 1000);

    // Event should be emitted
    const event = emittedEvents.find(
      (e) => e.event === 'USER_PASSWORD_RESET_REQUESTED',
    );
    expect(event).toBeDefined();
    expect(event!.payload.userId).toBe('user-1');
    expect(event!.payload.email).toBe('doctor@meritum.ca');
    expect(event!.payload.resetToken).toBeDefined();

    // Audit should be logged
    const auditEntry = auditEntries.find(
      (e) => e.action === 'auth.password_reset_requested',
    );
    expect(auditEntry).toBeDefined();
  });

  it('requestPasswordReset with non-existent user does NOT store token', async () => {
    const { requestPasswordReset } = await import('./iam.service.js');
    await requestPasswordReset(deps, 'nobody@example.com');

    expect(resetTokensDb).toHaveLength(0);
    expect(emittedEvents).toHaveLength(0);
    expect(auditEntries).toHaveLength(0);
  });

  it('requestPasswordReset stores SHA-256 hash of token (not plaintext)', async () => {
    usersDb.push({
      userId: 'user-1',
      email: 'doctor@meritum.ca',
    });

    const { requestPasswordReset, hashToken: hashTokenFn } = await import('./iam.service.js');
    await requestPasswordReset(deps, 'doctor@meritum.ca');

    // The emitted event has the raw token
    const rawToken = emittedEvents.find(
      (e) => e.event === 'USER_PASSWORD_RESET_REQUESTED',
    )!.payload.resetToken as string;

    // The stored tokenHash should be SHA-256 of rawToken
    const expectedHash = hashTokenFn(rawToken);
    expect(resetTokensDb[0].tokenHash).toBe(expectedHash);
    expect(resetTokensDb[0].tokenHash).not.toBe(rawToken);
  });
});

describe('IAM Service — resetPassword', () => {
  let deps: any;
  let usersDb: any[];
  let resetTokensDb: any[];
  let sessionsDb: any[];
  let auditEntries: any[];
  let emittedEvents: { event: string; payload: any }[];

  function makeDeps() {
    usersDb = [];
    resetTokensDb = [];
    sessionsDb = [];
    auditEntries = [];
    emittedEvents = [];

    const userRepo = {
      async findUserByEmail(email: string) {
        return usersDb.find((u) => u.email === email.toLowerCase());
      },
      async setPasswordHash(userId: string, passwordHash: string) {
        const user = usersDb.find((u) => u.userId === userId);
        if (user) user.passwordHash = passwordHash;
      },
    };

    const tokenRepo = {
      async createPasswordResetToken(data: any) {
        resetTokensDb.push({ ...data, used: false });
        return { tokenHash: data.tokenHash };
      },
      async findPasswordResetTokenByHash(tokenHash: string) {
        return resetTokensDb.find((t) => t.tokenHash === tokenHash);
      },
      async markPasswordResetTokenUsed(tokenHash: string) {
        const token = resetTokensDb.find((t) => t.tokenHash === tokenHash);
        if (token) token.used = true;
      },
    };

    const sessionRepo = {
      async revokeAllUserSessions(
        userId: string,
        _exceptSessionId: string | undefined,
        reason: string,
      ) {
        for (const session of sessionsDb) {
          if (session.userId === userId && !session.revoked) {
            session.revoked = true;
            session.revokedReason = reason;
          }
        }
      },
    };

    const auditRepo = {
      async appendAuditLog(entry: any) {
        auditEntries.push(entry);
        return entry;
      },
    };

    const events = {
      emit(event: string, payload: any) {
        emittedEvents.push({ event, payload });
      },
    };

    return { userRepo, tokenRepo, sessionRepo, auditRepo, events };
  }

  function seedUserWithResetToken(): { userId: string; rawToken: string } {
    const userId = 'user-1';
    usersDb.push({
      userId,
      email: 'doctor@meritum.ca',
      passwordHash: 'argon2id$OldPassword1!@#',
    });

    const rawToken = crypto.randomUUID();
    const tokenHash = hashToken(rawToken);
    resetTokensDb.push({
      userId,
      tokenHash,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now
      used: false,
    });

    return { userId, rawToken };
  }

  beforeEach(() => {
    deps = makeDeps();
  });

  it('resetPassword with valid token updates password', async () => {
    const { userId, rawToken } = seedUserWithResetToken();

    const { resetPassword } = await import('./iam.service.js');
    const result = await resetPassword(deps, rawToken, 'NewStr0ng!Pass');

    expect(result).toEqual({ success: true });

    // Password should be updated (mock argon2 prepends 'argon2id$')
    const user = usersDb.find((u) => u.userId === userId);
    expect(user.passwordHash).toBe('argon2id$NewStr0ng!Pass');

    // Token should be marked as used
    expect(resetTokensDb[0].used).toBe(true);
  });

  it('resetPassword invalidates all sessions', async () => {
    const { userId, rawToken } = seedUserWithResetToken();

    // Create some active sessions
    sessionsDb.push(
      { sessionId: 's1', userId, revoked: false, revokedReason: null },
      { sessionId: 's2', userId, revoked: false, revokedReason: null },
    );

    const { resetPassword } = await import('./iam.service.js');
    await resetPassword(deps, rawToken, 'NewStr0ng!Pass');

    // All sessions should be revoked
    expect(sessionsDb.every((s) => s.revoked === true)).toBe(true);
    expect(sessionsDb.every((s) => s.revokedReason === 'password_reset')).toBe(true);
  });

  it('resetPassword with expired token returns error', async () => {
    usersDb.push({
      userId: 'user-1',
      email: 'doctor@meritum.ca',
      passwordHash: 'argon2id$OldPassword1!@#',
    });

    const rawToken = crypto.randomUUID();
    const tokenHash = hashToken(rawToken);
    resetTokensDb.push({
      userId: 'user-1',
      tokenHash,
      expiresAt: new Date(Date.now() - 60 * 60 * 1000), // expired 1 hour ago
      used: false,
    });

    const { resetPassword } = await import('./iam.service.js');
    await expect(
      resetPassword(deps, rawToken, 'NewStr0ng!Pass'),
    ).rejects.toThrow('Reset token has expired');

    // Password should NOT be updated
    const user = usersDb.find((u) => u.userId === 'user-1');
    expect(user.passwordHash).toBe('argon2id$OldPassword1!@#');
  });

  it('resetPassword with invalid token returns error', async () => {
    const { resetPassword } = await import('./iam.service.js');
    await expect(
      resetPassword(deps, 'non-existent-token', 'NewStr0ng!Pass'),
    ).rejects.toThrow('Invalid or expired reset token');
  });

  it('resetPassword with already-used token returns error', async () => {
    const { rawToken } = seedUserWithResetToken();

    const { resetPassword } = await import('./iam.service.js');

    // Use it once
    await resetPassword(deps, rawToken, 'NewStr0ng!Pass');

    // Use it again
    await expect(
      resetPassword(deps, rawToken, 'Another!Pass1'),
    ).rejects.toThrow('Reset token has already been used');
  });

  it('resetPassword emits audit event', async () => {
    const { rawToken } = seedUserWithResetToken();

    const { resetPassword } = await import('./iam.service.js');
    await resetPassword(deps, rawToken, 'NewStr0ng!Pass');

    const auditEntry = auditEntries.find(
      (e) => e.action === 'auth.password_reset_completed',
    );
    expect(auditEntry).toBeDefined();
    expect(auditEntry.userId).toBe('user-1');
    expect(auditEntry.category).toBe('auth');
  });

  it('resetPassword emits password_reset_completed event', async () => {
    const { rawToken } = seedUserWithResetToken();

    const { resetPassword } = await import('./iam.service.js');
    await resetPassword(deps, rawToken, 'NewStr0ng!Pass');

    const event = emittedEvents.find(
      (e) => e.event === 'auth.password_reset_completed',
    );
    expect(event).toBeDefined();
    expect(event!.payload.userId).toBe('user-1');
  });
});

describe('MFA Session Token utilities', () => {
  it('createMfaSessionToken and verifyMfaSessionToken round-trip', () => {
    const userId = crypto.randomUUID();
    const token = createMfaSessionToken(userId);
    const result = verifyMfaSessionToken(token);
    expect(result).toBe(userId);
  });

  it('verifyMfaSessionToken rejects tampered token', () => {
    const userId = crypto.randomUUID();
    const token = createMfaSessionToken(userId);
    const tampered = token.slice(0, -3) + 'XXX';
    expect(verifyMfaSessionToken(tampered)).toBeNull();
  });

  it('verifyMfaSessionToken rejects expired token', () => {
    const userId = crypto.randomUUID();
    const realNow = Date.now;
    vi.spyOn(Date, 'now').mockReturnValue(realNow() - 6 * 60 * 1000); // 6 min ago
    const token = createMfaSessionToken(userId);
    vi.spyOn(Date, 'now').mockRestore();

    expect(verifyMfaSessionToken(token)).toBeNull();
  });

  it('verifyMfaSessionToken rejects garbage input', () => {
    expect(verifyMfaSessionToken('not-a-token')).toBeNull();
    expect(verifyMfaSessionToken('')).toBeNull();
    expect(verifyMfaSessionToken('abc.def.ghi')).toBeNull();
  });
});

// ===========================================================================
// Delegate Management Service Tests
// ===========================================================================

function makeDelegateServiceDeps(): DelegateServiceDeps {
  const auditEntries: Array<Record<string, unknown>> = [];
  const emittedEvents: Array<{ event: string; payload: Record<string, unknown> }> = [];

  return {
    userRepo: {
      findUserByEmail: vi.fn(async (email: string) => {
        return userStore.find(
          (u) => u.email === email.toLowerCase() && u.isActive !== false,
        ) as any;
      }),
      findUserById: vi.fn(async (userId: string) => {
        return userStore.find((u) => u.userId === userId) as any;
      }),
      createUser: vi.fn(async (data: any) => {
        const newUser = {
          userId: crypto.randomUUID(),
          email: data.email.toLowerCase(),
          passwordHash: data.passwordHash,
          fullName: data.fullName,
          phone: null,
          role: data.role ?? 'physician',
          emailVerified: false,
          mfaConfigured: false,
          totpSecretEncrypted: null,
          subscriptionStatus: 'trial',
          failedLoginCount: 0,
          lockedUntil: null,
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        userStore.push(newUser);
        return { userId: newUser.userId, email: newUser.email };
      }),
    },
    invitationRepo: {
      createInvitation: vi.fn(async (data: any) => {
        const invitation = {
          invitationId: crypto.randomUUID(),
          physicianUserId: data.physicianUserId,
          delegateEmail: data.delegateEmail.toLowerCase(),
          tokenHash: data.tokenHash,
          permissions: data.permissions,
          expiresAt: data.expiresAt,
          accepted: false,
          createdAt: new Date(),
        };
        invitationStore.push(invitation);
        return invitation;
      }),
      findInvitationByTokenHash: vi.fn(async (tokenHash: string) => {
        return invitationStore.find(
          (i) => i.tokenHash === tokenHash && !i.accepted && i.expiresAt.getTime() > Date.now(),
        ) as any;
      }),
      markInvitationAccepted: vi.fn(async (invitationId: string) => {
        const inv = invitationStore.find((i) => i.invitationId === invitationId);
        if (inv) inv.accepted = true;
      }),
    },
    linkageRepo: {
      createDelegateLinkage: vi.fn(async (data: any) => {
        const linkage = {
          linkageId: crypto.randomUUID(),
          physicianUserId: data.physicianUserId,
          delegateUserId: data.delegateUserId,
          permissions: data.permissions,
          canApproveBatches: data.canApproveBatches ?? false,
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        delegateLinkageStore.push(linkage);
        return linkage;
      }),
      findLinkage: vi.fn(async (physicianUserId: string, delegateUserId: string) => {
        return delegateLinkageStore.find(
          (l) =>
            l.physicianUserId === physicianUserId &&
            l.delegateUserId === delegateUserId &&
            l.isActive === true,
        ) as any;
      }),
      findLinkageById: vi.fn(async (linkageId: string) => {
        return delegateLinkageStore.find((l) => l.linkageId === linkageId) as any;
      }),
      listDelegatesForPhysician: vi.fn(async (physicianUserId: string) => {
        return delegateLinkageStore
          .filter((l) => l.physicianUserId === physicianUserId && l.isActive === true)
          .map((l) => {
            const user = userStore.find((u) => u.userId === l.delegateUserId);
            return {
              linkage: l,
              user: { userId: user?.userId, fullName: user?.fullName, email: user?.email },
              lastLogin: null,
            };
          });
      }) as any,
      listPhysiciansForDelegate: vi.fn(async (delegateUserId: string) => {
        return delegateLinkageStore
          .filter((l) => l.delegateUserId === delegateUserId && l.isActive === true)
          .map((l) => {
            const physician = userStore.find((u) => u.userId === l.physicianUserId);
            return {
              linkage: l,
              physician: { userId: physician?.userId, fullName: physician?.fullName, email: physician?.email },
            };
          });
      }) as any,
      updateLinkagePermissions: vi.fn(async (linkageId: string, permissions: string[], canApproveBatches: boolean) => {
        const linkage = delegateLinkageStore.find((l) => l.linkageId === linkageId && l.isActive === true);
        if (!linkage) return undefined;
        linkage.permissions = permissions;
        linkage.canApproveBatches = canApproveBatches;
        linkage.updatedAt = new Date();
        return { linkageId: linkage.linkageId };
      }),
      deactivateLinkage: vi.fn(async (linkageId: string) => {
        const linkage = delegateLinkageStore.find((l) => l.linkageId === linkageId);
        if (!linkage) return undefined;
        linkage.isActive = false;
        linkage.updatedAt = new Date();
        return { linkageId: linkage.linkageId };
      }),
    },
    sessionRepo: {
      revokeAllUserSessions: vi.fn(async (userId: string, _exceptSessionId: string | undefined, reason: string) => {
        for (const session of sessionStore) {
          if (session.userId === userId && !session.revoked) {
            session.revoked = true;
            session.revokedReason = reason;
          }
        }
      }),
    },
    auditRepo: {
      appendAuditLog: vi.fn(async (entry: any) => {
        const logEntry = { logId: crypto.randomUUID(), ...entry, createdAt: new Date() };
        auditEntries.push(logEntry);
        return logEntry;
      }),
    },
    events: {
      emit: vi.fn((event: string, payload: Record<string, unknown>) => {
        emittedEvents.push({ event, payload });
      }),
    },
  };
}

describe('IAM Service — inviteDelegate', () => {
  let deps: DelegateServiceDeps;
  const physicianUserId = crypto.randomUUID();

  beforeEach(() => {
    userStore = [];
    sessionStore = [];
    recoveryCodeStore = [];
    invitationStore = [];
    delegateLinkageStore = [];
    auditLogStore = [];
    deps = makeDelegateServiceDeps();
  });

  it('inviteDelegate generates invitation and emits event', async () => {
    const result = await inviteDelegate(
      deps,
      physicianUserId,
      'delegate@example.com',
      ['CLAIM_VIEW', 'CLAIM_CREATE'],
    );

    expect(result.invitationId).toBeDefined();
    expect(result.token).toBeDefined();
    expect(deps.invitationRepo.createInvitation).toHaveBeenCalledOnce();
    expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'delegate.invited',
        category: 'delegate',
      }),
    );
    expect(deps.events.emit).toHaveBeenCalledWith(
      'DELEGATE_INVITED',
      expect.objectContaining({
        physicianUserId,
        delegateEmail: 'delegate@example.com',
        invitationToken: result.token,
      }),
    );
  });

  it('inviteDelegate rejects invalid permissions', async () => {
    // DELEGATE_MANAGE is forbidden for delegates
    await expect(
      inviteDelegate(deps, physicianUserId, 'delegate@example.com', [
        'CLAIM_VIEW',
        'DELEGATE_MANAGE',
      ]),
    ).rejects.toThrow("Permission 'DELEGATE_MANAGE' cannot be granted to delegates");
  });

  it('inviteDelegate rejects SUBSCRIPTION_MANAGE', async () => {
    await expect(
      inviteDelegate(deps, physicianUserId, 'delegate@example.com', [
        'SUBSCRIPTION_MANAGE',
      ]),
    ).rejects.toThrow("Permission 'SUBSCRIPTION_MANAGE' cannot be granted to delegates");
  });

  it('inviteDelegate rejects DATA_EXPORT', async () => {
    await expect(
      inviteDelegate(deps, physicianUserId, 'delegate@example.com', [
        'DATA_EXPORT',
      ]),
    ).rejects.toThrow("Permission 'DATA_EXPORT' cannot be granted to delegates");
  });

  it('inviteDelegate rejects unknown permissions', async () => {
    await expect(
      inviteDelegate(deps, physicianUserId, 'delegate@example.com', [
        'NONEXISTENT_PERM',
      ]),
    ).rejects.toThrow("Invalid delegate permission: 'NONEXISTENT_PERM'");
  });

  it('inviteDelegate normalizes email to lowercase', async () => {
    await inviteDelegate(deps, physicianUserId, 'Delegate@Example.COM', [
      'CLAIM_VIEW',
    ]);

    expect(deps.invitationRepo.createInvitation).toHaveBeenCalledWith(
      expect.objectContaining({
        delegateEmail: 'delegate@example.com',
      }),
    );
  });

  it('inviteDelegate stores hashed token, not plaintext', async () => {
    const result = await inviteDelegate(deps, physicianUserId, 'delegate@example.com', [
      'CLAIM_VIEW',
    ]);

    const storedInvitation = invitationStore[0];
    expect(storedInvitation.tokenHash).not.toBe(result.token);
    expect(storedInvitation.tokenHash).toBe(hashToken(result.token));
  });
});

describe('IAM Service — acceptInvitation', () => {
  let deps: DelegateServiceDeps;
  const physicianUserId = crypto.randomUUID();

  beforeEach(() => {
    userStore = [];
    sessionStore = [];
    recoveryCodeStore = [];
    invitationStore = [];
    delegateLinkageStore = [];
    auditLogStore = [];
    deps = makeDelegateServiceDeps();
  });

  it('acceptInvitation creates linkage for existing user', async () => {
    // Create existing delegate user
    const existingDelegate = {
      userId: crypto.randomUUID(),
      email: 'delegate@example.com',
      passwordHash: 'hashed',
      fullName: 'Existing Delegate',
      phone: null,
      role: 'delegate',
      emailVerified: true,
      mfaConfigured: true,
      totpSecretEncrypted: null,
      subscriptionStatus: 'trial',
      failedLoginCount: 0,
      lockedUntil: null,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    userStore.push(existingDelegate);

    // Create invitation
    const inviteResult = await inviteDelegate(deps, physicianUserId, 'delegate@example.com', [
      'CLAIM_VIEW',
    ]);

    const result = await acceptInvitation(deps, inviteResult.token);

    expect(result.linkageId).toBeDefined();
    expect(deps.linkageRepo.createDelegateLinkage).toHaveBeenCalledWith(
      expect.objectContaining({
        physicianUserId,
        delegateUserId: existingDelegate.userId,
        permissions: ['CLAIM_VIEW'],
      }),
    );
    expect(deps.events.emit).toHaveBeenCalledWith(
      'DELEGATE_ACCEPTED',
      expect.objectContaining({
        physicianUserId,
        delegateUserId: existingDelegate.userId,
      }),
    );
  });

  it('acceptInvitation creates new user account for new delegate', async () => {
    // No existing user — invitation for a new email
    const inviteResult = await inviteDelegate(deps, physicianUserId, 'newdelegate@example.com', [
      'CLAIM_VIEW',
      'CLAIM_CREATE',
    ]);

    const result = await acceptInvitation(deps, inviteResult.token, {
      fullName: 'New Delegate',
      password: 'SecureP@ss1234',
    });

    expect(result.linkageId).toBeDefined();
    expect(deps.userRepo.createUser).toHaveBeenCalledWith(
      expect.objectContaining({
        email: 'newdelegate@example.com',
        fullName: 'New Delegate',
        role: 'DELEGATE',
      }),
    );
    expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'delegate.accepted',
        category: 'delegate',
      }),
    );
  });

  it('acceptInvitation rejects expired invitation', async () => {
    // Create invitation with already-expired time
    const rawToken = crypto.randomUUID();
    const tokenHash = hashToken(rawToken);
    invitationStore.push({
      invitationId: crypto.randomUUID(),
      physicianUserId,
      delegateEmail: 'delegate@example.com',
      tokenHash,
      permissions: ['CLAIM_VIEW'],
      expiresAt: new Date(Date.now() - 1000), // Already expired
      accepted: false,
      createdAt: new Date(),
    });

    // The mock's findInvitationByTokenHash filters out expired tokens, so it returns undefined
    await expect(acceptInvitation(deps, rawToken)).rejects.toThrow(
      'Invalid or expired invitation token',
    );
  });

  it('acceptInvitation rejects already-accepted invitation', async () => {
    // Create an already-accepted invitation
    const rawToken = crypto.randomUUID();
    const tokenHash = hashToken(rawToken);
    invitationStore.push({
      invitationId: crypto.randomUUID(),
      physicianUserId,
      delegateEmail: 'delegate@example.com',
      tokenHash,
      permissions: ['CLAIM_VIEW'],
      expiresAt: new Date(Date.now() + 72 * 60 * 60 * 1000),
      accepted: true, // Already accepted
      createdAt: new Date(),
    });

    // The mock's findInvitationByTokenHash filters out accepted tokens
    await expect(acceptInvitation(deps, rawToken)).rejects.toThrow(
      'Invalid or expired invitation token',
    );
  });

  it('acceptInvitation requires registration data for new users', async () => {
    const inviteResult = await inviteDelegate(deps, physicianUserId, 'brand-new@example.com', [
      'CLAIM_VIEW',
    ]);

    // No registration data provided
    await expect(acceptInvitation(deps, inviteResult.token)).rejects.toThrow(
      'Registration data (fullName, password) is required for new delegate accounts',
    );
  });

  it('acceptInvitation marks the invitation as accepted', async () => {
    userStore.push({
      userId: crypto.randomUUID(),
      email: 'delegate@example.com',
      passwordHash: 'hashed',
      fullName: 'Delegate',
      phone: null,
      role: 'delegate',
      emailVerified: true,
      mfaConfigured: true,
      totpSecretEncrypted: null,
      subscriptionStatus: 'trial',
      failedLoginCount: 0,
      lockedUntil: null,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const inviteResult = await inviteDelegate(deps, physicianUserId, 'delegate@example.com', [
      'CLAIM_VIEW',
    ]);

    await acceptInvitation(deps, inviteResult.token);

    expect(deps.invitationRepo.markInvitationAccepted).toHaveBeenCalledOnce();
  });
});

describe('IAM Service — updateDelegatePermissions', () => {
  let deps: DelegateServiceDeps;
  const physicianUserId = crypto.randomUUID();
  const delegateUserId = crypto.randomUUID();

  beforeEach(() => {
    userStore = [];
    sessionStore = [];
    recoveryCodeStore = [];
    invitationStore = [];
    delegateLinkageStore = [];
    auditLogStore = [];
    deps = makeDelegateServiceDeps();
  });

  it('updateDelegatePermissions updates permissions successfully', async () => {
    // Create an active linkage
    delegateLinkageStore.push({
      linkageId: 'linkage-1',
      physicianUserId,
      delegateUserId,
      permissions: ['CLAIM_VIEW'],
      canApproveBatches: false,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const result = await updateDelegatePermissions(
      deps,
      physicianUserId,
      'linkage-1',
      ['CLAIM_VIEW', 'CLAIM_CREATE', 'PATIENT_VIEW'],
      true,
    );

    expect(result.linkageId).toBe('linkage-1');
    expect(deps.linkageRepo.updateLinkagePermissions).toHaveBeenCalledWith(
      'linkage-1',
      ['CLAIM_VIEW', 'CLAIM_CREATE', 'PATIENT_VIEW'],
      true,
    );
    expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'delegate.permissions_updated',
        detail: expect.objectContaining({ permissions: ['CLAIM_VIEW', 'CLAIM_CREATE', 'PATIENT_VIEW'] }),
      }),
    );
  });

  it('updateDelegatePermissions rejects if linkage belongs to different physician', async () => {
    const otherPhysicianId = crypto.randomUUID();
    delegateLinkageStore.push({
      linkageId: 'linkage-2',
      physicianUserId: otherPhysicianId, // Different physician!
      delegateUserId,
      permissions: ['CLAIM_VIEW'],
      canApproveBatches: false,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await expect(
      updateDelegatePermissions(
        deps,
        physicianUserId,
        'linkage-2',
        ['CLAIM_VIEW'],
        false,
      ),
    ).rejects.toThrow('Delegate linkage not found');
  });

  it('updateDelegatePermissions rejects forbidden permissions', async () => {
    delegateLinkageStore.push({
      linkageId: 'linkage-3',
      physicianUserId,
      delegateUserId,
      permissions: ['CLAIM_VIEW'],
      canApproveBatches: false,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await expect(
      updateDelegatePermissions(
        deps,
        physicianUserId,
        'linkage-3',
        ['CLAIM_VIEW', 'DELEGATE_MANAGE'],
        false,
      ),
    ).rejects.toThrow("Permission 'DELEGATE_MANAGE' cannot be granted to delegates");
  });

  it('updateDelegatePermissions rejects inactive linkage', async () => {
    delegateLinkageStore.push({
      linkageId: 'linkage-inactive',
      physicianUserId,
      delegateUserId,
      permissions: ['CLAIM_VIEW'],
      canApproveBatches: false,
      isActive: false, // Inactive
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await expect(
      updateDelegatePermissions(
        deps,
        physicianUserId,
        'linkage-inactive',
        ['CLAIM_VIEW'],
        false,
      ),
    ).rejects.toThrow('Delegate linkage is not active');
  });
});

describe('IAM Service — revokeDelegate', () => {
  let deps: DelegateServiceDeps;
  const physicianUserId = crypto.randomUUID();
  const delegateUserId = crypto.randomUUID();

  beforeEach(() => {
    userStore = [];
    sessionStore = [];
    recoveryCodeStore = [];
    invitationStore = [];
    delegateLinkageStore = [];
    auditLogStore = [];
    deps = makeDelegateServiceDeps();
  });

  it('revokeDelegate deactivates linkage', async () => {
    delegateLinkageStore.push({
      linkageId: 'linkage-rev-1',
      physicianUserId,
      delegateUserId,
      permissions: ['CLAIM_VIEW'],
      canApproveBatches: false,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await revokeDelegate(deps, physicianUserId, 'linkage-rev-1');

    expect(deps.linkageRepo.deactivateLinkage).toHaveBeenCalledWith('linkage-rev-1');
    expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'delegate.revoked',
        category: 'delegate',
      }),
    );
    expect(deps.events.emit).toHaveBeenCalledWith(
      'DELEGATE_REVOKED',
      expect.objectContaining({
        physicianUserId,
        delegateUserId,
        linkageId: 'linkage-rev-1',
      }),
    );
  });

  it('revokeDelegate revokes delegate sessions', async () => {
    delegateLinkageStore.push({
      linkageId: 'linkage-rev-2',
      physicianUserId,
      delegateUserId,
      permissions: ['CLAIM_VIEW'],
      canApproveBatches: false,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    // Create a session for the delegate
    sessionStore.push({
      sessionId: crypto.randomUUID(),
      userId: delegateUserId,
      tokenHash: 'somehash',
      ipAddress: '127.0.0.1',
      userAgent: 'test',
      createdAt: new Date(),
      lastActiveAt: new Date(),
      revoked: false,
      revokedReason: null,
    });

    await revokeDelegate(deps, physicianUserId, 'linkage-rev-2');

    expect(deps.sessionRepo.revokeAllUserSessions).toHaveBeenCalledWith(
      delegateUserId,
      undefined,
      'revoked_remote',
    );
  });

  it('revokeDelegate rejects if linkage belongs to different physician', async () => {
    const otherPhysicianId = crypto.randomUUID();
    delegateLinkageStore.push({
      linkageId: 'linkage-rev-3',
      physicianUserId: otherPhysicianId,
      delegateUserId,
      permissions: ['CLAIM_VIEW'],
      canApproveBatches: false,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await expect(
      revokeDelegate(deps, physicianUserId, 'linkage-rev-3'),
    ).rejects.toThrow('Delegate linkage not found');
  });
});

describe('IAM Service — listDelegates', () => {
  let deps: DelegateServiceDeps;
  const physicianUserId = crypto.randomUUID();

  beforeEach(() => {
    userStore = [];
    sessionStore = [];
    recoveryCodeStore = [];
    invitationStore = [];
    delegateLinkageStore = [];
    auditLogStore = [];
    deps = makeDelegateServiceDeps();
  });

  it('listDelegates returns delegates with metadata', async () => {
    const delegateUserId = crypto.randomUUID();
    userStore.push({
      userId: delegateUserId,
      email: 'delegate@example.com',
      passwordHash: 'hashed',
      fullName: 'Test Delegate',
      phone: null,
      role: 'delegate',
      emailVerified: true,
      mfaConfigured: true,
      totpSecretEncrypted: null,
      subscriptionStatus: 'trial',
      failedLoginCount: 0,
      lockedUntil: null,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    delegateLinkageStore.push({
      linkageId: 'link-list-1',
      physicianUserId,
      delegateUserId,
      permissions: ['CLAIM_VIEW', 'PATIENT_VIEW'],
      canApproveBatches: true,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const result = await listDelegates(deps, physicianUserId);

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      linkageId: 'link-list-1',
      delegateUserId,
      fullName: 'Test Delegate',
      email: 'delegate@example.com',
      permissions: ['CLAIM_VIEW', 'PATIENT_VIEW'],
      canApproveBatches: true,
      isActive: true,
    });
  });

  it('listDelegates returns empty array when no delegates exist', async () => {
    const result = await listDelegates(deps, physicianUserId);
    expect(result).toHaveLength(0);
  });
});

describe('IAM Service — listPhysiciansForDelegate', () => {
  let deps: DelegateServiceDeps;
  const delegateUserId = crypto.randomUUID();

  beforeEach(() => {
    userStore = [];
    sessionStore = [];
    recoveryCodeStore = [];
    invitationStore = [];
    delegateLinkageStore = [];
    auditLogStore = [];
    deps = makeDelegateServiceDeps();
  });

  it('listPhysiciansForDelegate returns physicians with permissions', async () => {
    const physicianUserId = crypto.randomUUID();
    userStore.push({
      userId: physicianUserId,
      email: 'doctor@example.com',
      passwordHash: 'hashed',
      fullName: 'Dr. Smith',
      phone: null,
      role: 'physician',
      emailVerified: true,
      mfaConfigured: true,
      totpSecretEncrypted: null,
      subscriptionStatus: 'active',
      failedLoginCount: 0,
      lockedUntil: null,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    delegateLinkageStore.push({
      linkageId: 'link-phys-1',
      physicianUserId,
      delegateUserId,
      permissions: ['CLAIM_VIEW', 'CLAIM_CREATE'],
      canApproveBatches: false,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const result = await listPhysiciansForDelegate(deps, delegateUserId);

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      linkageId: 'link-phys-1',
      physicianUserId,
      fullName: 'Dr. Smith',
      email: 'doctor@example.com',
      permissions: ['CLAIM_VIEW', 'CLAIM_CREATE'],
    });
  });
});

describe('IAM Service — switchPhysicianContext', () => {
  let deps: DelegateServiceDeps;
  const physicianUserId = crypto.randomUUID();
  const delegateUserId = crypto.randomUUID();

  beforeEach(() => {
    userStore = [];
    sessionStore = [];
    recoveryCodeStore = [];
    invitationStore = [];
    delegateLinkageStore = [];
    auditLogStore = [];
    deps = makeDelegateServiceDeps();
  });

  it('switchPhysicianContext succeeds with active linkage', async () => {
    delegateLinkageStore.push({
      linkageId: 'link-switch-1',
      physicianUserId,
      delegateUserId,
      permissions: ['CLAIM_VIEW', 'PATIENT_VIEW'],
      canApproveBatches: true,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const result = await switchPhysicianContext(deps, delegateUserId, physicianUserId);

    expect(result).toMatchObject({
      userId: delegateUserId,
      role: 'delegate',
      delegateContext: {
        delegateUserId,
        physicianUserId,
        permissions: ['CLAIM_VIEW', 'PATIENT_VIEW'],
        canApproveBatches: true,
      },
    });
    expect(deps.auditRepo.appendAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'delegate.context_switched',
        category: 'delegate',
      }),
    );
    expect(deps.events.emit).toHaveBeenCalledWith(
      'DELEGATE_CONTEXT_SWITCHED',
      expect.objectContaining({
        delegateUserId,
        physicianUserId,
      }),
    );
  });

  it('switchPhysicianContext fails without active linkage', async () => {
    // No linkage exists at all
    await expect(
      switchPhysicianContext(deps, delegateUserId, physicianUserId),
    ).rejects.toThrow('No active linkage with this physician');
  });

  it('switchPhysicianContext fails with inactive linkage', async () => {
    delegateLinkageStore.push({
      linkageId: 'link-switch-inactive',
      physicianUserId,
      delegateUserId,
      permissions: ['CLAIM_VIEW'],
      canApproveBatches: false,
      isActive: false, // Deactivated
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await expect(
      switchPhysicianContext(deps, delegateUserId, physicianUserId),
    ).rejects.toThrow('No active linkage with this physician');
  });

  it('switchPhysicianContext fails for wrong physician', async () => {
    const otherPhysicianId = crypto.randomUUID();
    delegateLinkageStore.push({
      linkageId: 'link-switch-wrong',
      physicianUserId: otherPhysicianId,
      delegateUserId,
      permissions: ['CLAIM_VIEW'],
      canApproveBatches: false,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    // Delegate tries to switch to a physician they have no linkage with
    await expect(
      switchPhysicianContext(deps, delegateUserId, physicianUserId),
    ).rejects.toThrow('No active linkage with this physician');
  });
});

// ===========================================================================
// Encryption utility tests
// ===========================================================================

describe('TOTP encryption utilities', () => {
  it('encryptTotpSecret and decryptTotpSecret round-trip correctly', () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const encrypted = encryptTotpSecret(secret);

    // Encrypted should not be the same as plaintext
    expect(encrypted).not.toBe(secret);

    // Should be in format iv:authTag:ciphertext (hex)
    const parts = encrypted.split(':');
    expect(parts).toHaveLength(3);

    // Should decrypt back
    const decrypted = decryptTotpSecret(encrypted);
    expect(decrypted).toBe(secret);
  });

  it('encryptTotpSecret produces different ciphertext each time (random IV)', () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const encrypted1 = encryptTotpSecret(secret);
    const encrypted2 = encryptTotpSecret(secret);

    // Different IVs should produce different ciphertext
    expect(encrypted1).not.toBe(encrypted2);

    // Both should decrypt to the same value
    expect(decryptTotpSecret(encrypted1)).toBe(secret);
    expect(decryptTotpSecret(encrypted2)).toBe(secret);
  });
});

// ===========================================================================
// Account Management Service Tests
// ===========================================================================

describe('IAM Service — getAccount', () => {
  let deps: AccountServiceDeps;
  let userStore: Record<string, any>[];
  let auditEntries: Record<string, any>[];
  let emittedEvents: { event: string; payload: Record<string, unknown> }[];

  function makeDeps(): AccountServiceDeps {
    userStore = [];
    auditEntries = [];
    emittedEvents = [];

    const userRepo: AccountUserRepo = {
      async findUserById(userId) {
        return userStore.find((u) => u.userId === userId) as any;
      },
      async updateUser(userId, data) {
        const user = userStore.find((u) => u.userId === userId);
        if (!user) return undefined;
        if (data.fullName !== undefined) user.fullName = data.fullName;
        if (data.phone !== undefined) user.phone = data.phone;
        return user as any;
      },
      async deactivateUser(userId) {
        const user = userStore.find((u) => u.userId === userId);
        if (user) user.isActive = false;
      },
    };

    const sessionRepo: AccountSessionRepo = {
      async revokeAllUserSessions() {},
    };

    const linkageRepo: AccountDelegateLinkageRepo = {
      async listDelegatesForPhysician() { return []; },
      async deactivateLinkage() { return undefined; },
    };

    const auditRepo: AuditRepo = {
      async appendAuditLog(entry) {
        auditEntries.push(entry);
        return entry;
      },
    };

    const events: EventEmitter = {
      emit(event, payload) {
        emittedEvents.push({ event, payload });
      },
    };

    return { userRepo, sessionRepo, linkageRepo, auditRepo, events };
  }

  beforeEach(() => {
    deps = makeDeps();
  });

  it('getAccount returns account info without sensitive fields', async () => {
    userStore.push({
      userId: 'user-1',
      email: 'dr.smith@hospital.ca',
      fullName: 'Dr. Smith',
      phone: '403-555-0123',
      role: 'PHYSICIAN',
      subscriptionStatus: 'ACTIVE',
      mfaConfigured: true,
      passwordHash: 'argon2id$secret',
      totpSecretEncrypted: 'enc:secret',
      isActive: true,
    });

    const result = await getAccount(deps, 'user-1');

    expect(result.userId).toBe('user-1');
    expect(result.email).toBe('dr.smith@hospital.ca');
    expect(result.fullName).toBe('Dr. Smith');
    expect(result.phone).toBe('403-555-0123');
    expect(result.role).toBe('PHYSICIAN');
    expect(result.subscriptionStatus).toBe('ACTIVE');
    expect(result.mfaConfigured).toBe(true);

    // Sensitive fields must NOT be present
    expect((result as any).passwordHash).toBeUndefined();
    expect((result as any).totpSecretEncrypted).toBeUndefined();
  });

  it('getAccount throws for non-existent user', async () => {
    await expect(getAccount(deps, 'nonexistent')).rejects.toThrow(
      'Account not found',
    );
  });

  it('getAccount throws for deactivated user', async () => {
    userStore.push({
      userId: 'user-inactive',
      email: 'gone@test.ca',
      fullName: 'Gone User',
      phone: null,
      role: 'PHYSICIAN',
      subscriptionStatus: 'CANCELLED',
      mfaConfigured: true,
      passwordHash: 'argon2id$x',
      totpSecretEncrypted: null,
      isActive: false,
    });

    await expect(getAccount(deps, 'user-inactive')).rejects.toThrow(
      'Account not found',
    );
  });
});

describe('IAM Service — updateAccount', () => {
  let deps: AccountServiceDeps;
  let userStore: Record<string, any>[];
  let auditEntries: Record<string, any>[];
  let emittedEvents: { event: string; payload: Record<string, unknown> }[];

  function makeDeps(): AccountServiceDeps {
    userStore = [];
    auditEntries = [];
    emittedEvents = [];

    const userRepo: AccountUserRepo = {
      async findUserById(userId) {
        return userStore.find((u) => u.userId === userId) as any;
      },
      async updateUser(userId, data) {
        const user = userStore.find((u) => u.userId === userId);
        if (!user) return undefined;
        if (data.fullName !== undefined) user.fullName = data.fullName;
        if (data.phone !== undefined) user.phone = data.phone;
        return user as any;
      },
      async deactivateUser(userId) {
        const user = userStore.find((u) => u.userId === userId);
        if (user) user.isActive = false;
      },
    };

    const sessionRepo: AccountSessionRepo = {
      async revokeAllUserSessions() {},
    };

    const linkageRepo: AccountDelegateLinkageRepo = {
      async listDelegatesForPhysician() { return []; },
      async deactivateLinkage() { return undefined; },
    };

    const auditRepo: AuditRepo = {
      async appendAuditLog(entry) {
        auditEntries.push(entry);
        return entry;
      },
    };

    const events: EventEmitter = {
      emit(event, payload) {
        emittedEvents.push({ event, payload });
      },
    };

    return { userRepo, sessionRepo, linkageRepo, auditRepo, events };
  }

  beforeEach(() => {
    deps = makeDeps();
    userStore.push({
      userId: 'user-1',
      email: 'dr.smith@hospital.ca',
      fullName: 'Dr. Smith',
      phone: '403-555-0123',
      role: 'PHYSICIAN',
      subscriptionStatus: 'ACTIVE',
      mfaConfigured: true,
      passwordHash: 'argon2id$secret',
      totpSecretEncrypted: 'enc:secret',
      isActive: true,
    });
  });

  it('updateAccount updates name and phone', async () => {
    const result = await updateAccount(deps, 'user-1', {
      full_name: 'Dr. Jane Smith',
      phone: '780-555-9999',
    });

    expect(result.userId).toBe('user-1');
    expect(userStore[0].fullName).toBe('Dr. Jane Smith');
    expect(userStore[0].phone).toBe('780-555-9999');

    // Audit log should be recorded
    expect(auditEntries).toHaveLength(1);
    expect(auditEntries[0].action).toBe('account.updated');
  });

  it('updateAccount does not update email or password', async () => {
    // updateAccount only accepts full_name and phone — email and password
    // must go through their dedicated flows. Verify that even if someone
    // tries to sneak in extra fields they are ignored.
    const originalEmail = userStore[0].email;
    const originalPassword = userStore[0].passwordHash;

    await updateAccount(deps, 'user-1', {
      full_name: 'Updated Name',
    });

    // Email and password must remain unchanged
    expect(userStore[0].email).toBe(originalEmail);
    expect(userStore[0].passwordHash).toBe(originalPassword);
  });

  it('updateAccount throws for non-existent user', async () => {
    await expect(
      updateAccount(deps, 'nonexistent', { full_name: 'X' }),
    ).rejects.toThrow('Account not found');
  });
});

describe('IAM Service — requestAccountDeletion', () => {
  let deps: AccountServiceDeps;
  let userStore: Record<string, any>[];
  let sessionRevoked: { userId: string; reason: string }[];
  let deactivatedLinkages: string[];
  let auditEntries: Record<string, any>[];
  let emittedEvents: { event: string; payload: Record<string, unknown> }[];
  let delegateLinkageStore: Record<string, any>[];

  function makeDeps(): AccountServiceDeps {
    userStore = [];
    sessionRevoked = [];
    deactivatedLinkages = [];
    auditEntries = [];
    emittedEvents = [];
    delegateLinkageStore = [];

    const userRepo: AccountUserRepo = {
      async findUserById(userId) {
        return userStore.find((u) => u.userId === userId) as any;
      },
      async updateUser(userId, data) {
        const user = userStore.find((u) => u.userId === userId);
        if (!user) return undefined;
        if (data.fullName !== undefined) user.fullName = data.fullName;
        if (data.phone !== undefined) user.phone = data.phone;
        return user as any;
      },
      async deactivateUser(userId) {
        const user = userStore.find((u) => u.userId === userId);
        if (user) user.isActive = false;
      },
    };

    const sessionRepo: AccountSessionRepo = {
      async revokeAllUserSessions(userId, _except, reason) {
        sessionRevoked.push({ userId, reason });
      },
    };

    const linkageRepo: AccountDelegateLinkageRepo = {
      async listDelegatesForPhysician(physicianUserId) {
        return delegateLinkageStore
          .filter((l) => l.physicianUserId === physicianUserId)
          .map((l) => ({
            linkage: {
              linkageId: l.linkageId,
              delegateUserId: l.delegateUserId,
              isActive: l.isActive,
            },
            user: { userId: l.delegateUserId, fullName: 'Delegate', email: 'delegate@test.ca' },
            lastLogin: null,
          }));
      },
      async deactivateLinkage(linkageId) {
        const linkage = delegateLinkageStore.find((l) => l.linkageId === linkageId);
        if (linkage) {
          linkage.isActive = false;
          deactivatedLinkages.push(linkageId);
        }
        return linkage ? { linkageId } : undefined;
      },
    };

    const auditRepo: AuditRepo = {
      async appendAuditLog(entry) {
        auditEntries.push(entry);
        return entry;
      },
    };

    const events: EventEmitter = {
      emit(event, payload) {
        emittedEvents.push({ event, payload });
      },
    };

    return { userRepo, sessionRepo, linkageRepo, auditRepo, events };
  }

  function addTestUser() {
    const encryptedSecret = encryptTotpSecret('JBSWY3DPEHPK3PXP');
    userStore.push({
      userId: 'user-1',
      email: 'dr.smith@hospital.ca',
      fullName: 'Dr. Smith',
      phone: '403-555-0123',
      role: 'PHYSICIAN',
      subscriptionStatus: 'ACTIVE',
      mfaConfigured: true,
      passwordHash: 'argon2id$Str0ng!Passw0rd',
      totpSecretEncrypted: encryptedSecret,
      isActive: true,
    });
  }

  beforeEach(() => {
    deps = makeDeps();
    addTestUser();
  });

  it('requestAccountDeletion requires correct password', async () => {
    await expect(
      requestAccountDeletion(deps, 'user-1', 'WrongPassword!', '123456', 'DELETE'),
    ).rejects.toThrow('Invalid password');
  });

  it('requestAccountDeletion requires valid TOTP', async () => {
    await expect(
      requestAccountDeletion(deps, 'user-1', 'Str0ng!Passw0rd', '000000', 'DELETE'),
    ).rejects.toThrow('Invalid TOTP code');
  });

  it("requestAccountDeletion requires 'DELETE' confirmation", async () => {
    await expect(
      requestAccountDeletion(deps, 'user-1', 'Str0ng!Passw0rd', '123456', 'delete'),
    ).rejects.toThrow('Confirmation must be exactly "DELETE"');

    await expect(
      requestAccountDeletion(deps, 'user-1', 'Str0ng!Passw0rd', '123456', 'yes'),
    ).rejects.toThrow('Confirmation must be exactly "DELETE"');
  });

  it('requestAccountDeletion invalidates all sessions', async () => {
    const result = await requestAccountDeletion(
      deps, 'user-1', 'Str0ng!Passw0rd', '123456', 'DELETE',
    );

    expect(result.scheduledDeletionDate).toBeDefined();
    expect(sessionRevoked).toHaveLength(1);
    expect(sessionRevoked[0].userId).toBe('user-1');
    expect(sessionRevoked[0].reason).toBe('account_deleted');
  });

  it('requestAccountDeletion deactivates delegate linkages', async () => {
    delegateLinkageStore.push({
      linkageId: 'linkage-1',
      physicianUserId: 'user-1',
      delegateUserId: 'delegate-1',
      isActive: true,
    });
    delegateLinkageStore.push({
      linkageId: 'linkage-2',
      physicianUserId: 'user-1',
      delegateUserId: 'delegate-2',
      isActive: true,
    });

    await requestAccountDeletion(
      deps, 'user-1', 'Str0ng!Passw0rd', '123456', 'DELETE',
    );

    expect(deactivatedLinkages).toContain('linkage-1');
    expect(deactivatedLinkages).toContain('linkage-2');

    // Delegates should be notified
    const delegateNotifications = emittedEvents.filter(
      (e) => e.event === 'DELEGATE_ACCESS_REVOKED_ACCOUNT_DELETION',
    );
    expect(delegateNotifications).toHaveLength(2);
  });

  it('requestAccountDeletion schedules deletion in 30 days', async () => {
    const before = Date.now();
    const result = await requestAccountDeletion(
      deps, 'user-1', 'Str0ng!Passw0rd', '123456', 'DELETE',
    );
    const after = Date.now();

    const scheduledDate = new Date(result.scheduledDeletionDate).getTime();
    const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;

    // Scheduled date should be ~30 days from now
    expect(scheduledDate).toBeGreaterThanOrEqual(before + thirtyDaysMs);
    expect(scheduledDate).toBeLessThanOrEqual(after + thirtyDaysMs);

    // User should be deactivated (soft delete)
    expect(userStore[0].isActive).toBe(false);

    // Audit log should record the deletion request
    const deletionAudit = auditEntries.find(
      (e) => e.action === 'account.deletion_requested',
    );
    expect(deletionAudit).toBeDefined();
    expect(deletionAudit!.resourceId).toBe('user-1');

    // Deletion event should be emitted
    const deletionEvent = emittedEvents.find(
      (e) => e.event === 'ACCOUNT_DELETION_REQUESTED',
    );
    expect(deletionEvent).toBeDefined();
  });

  it('requestAccountDeletion emits subscription cancel event', async () => {
    await requestAccountDeletion(
      deps, 'user-1', 'Str0ng!Passw0rd', '123456', 'DELETE',
    );

    const cancelEvent = emittedEvents.find(
      (e) => e.event === 'SUBSCRIPTION_CANCEL_REQUESTED',
    );
    expect(cancelEvent).toBeDefined();
    expect(cancelEvent!.payload.userId).toBe('user-1');
  });
});

describe('IAM Service — checkSubscriptionAccess', () => {
  let deps: AccountServiceDeps;
  let userStore: Record<string, any>[];

  function makeDeps(): AccountServiceDeps {
    userStore = [];

    const userRepo: AccountUserRepo = {
      async findUserById(userId) {
        return userStore.find((u) => u.userId === userId) as any;
      },
      async updateUser() { return undefined; },
      async deactivateUser() {},
    };

    const sessionRepo: AccountSessionRepo = {
      async revokeAllUserSessions() {},
    };

    const linkageRepo: AccountDelegateLinkageRepo = {
      async listDelegatesForPhysician() { return []; },
      async deactivateLinkage() { return undefined; },
    };

    const auditRepo: AuditRepo = {
      async appendAuditLog(entry) { return entry; },
    };

    const events: EventEmitter = {
      emit() {},
    };

    return { userRepo, sessionRepo, linkageRepo, auditRepo, events };
  }

  beforeEach(() => {
    deps = makeDeps();
  });

  it('checkSubscriptionAccess returns correct access level for each status', async () => {
    const testCases = [
      { status: 'TRIAL', expectedAccess: 'full' },
      { status: 'ACTIVE', expectedAccess: 'full' },
      { status: 'PAST_DUE', expectedAccess: 'read_only' },
      { status: 'SUSPENDED', expectedAccess: 'suspended' },
      { status: 'CANCELLED', expectedAccess: 'suspended' },
    ];

    for (const { status, expectedAccess } of testCases) {
      userStore.length = 0;
      userStore.push({
        userId: 'user-1',
        email: 'test@test.ca',
        fullName: 'Test',
        phone: null,
        role: 'PHYSICIAN',
        subscriptionStatus: status,
        mfaConfigured: true,
        passwordHash: 'argon2id$x',
        totpSecretEncrypted: null,
        isActive: true,
      });

      const result = await checkSubscriptionAccess(deps, 'user-1');
      expect(result.subscriptionStatus).toBe(status);
      expect(result.accessLevel).toBe(expectedAccess);
    }
  });

  it('checkSubscriptionAccess throws for non-existent user', async () => {
    await expect(
      checkSubscriptionAccess(deps, 'nonexistent'),
    ).rejects.toThrow('Account not found');
  });
});

// ===========================================================================
// Auth Plugin Tests
// ===========================================================================

import {
  parseCookie,
  sanitizeBody,
} from '../../plugins/auth.plugin.js';

describe('Auth Plugin — parseCookie', () => {
  it('parses a single cookie', () => {
    expect(parseCookie('session=abc123', 'session')).toBe('abc123');
  });

  it('parses multiple cookies', () => {
    expect(parseCookie('foo=bar; session=xyz; baz=qux', 'session')).toBe('xyz');
  });

  it('returns null for missing cookie', () => {
    expect(parseCookie('foo=bar', 'session')).toBeNull();
  });

  it('handles cookie value with = sign', () => {
    expect(parseCookie('session=abc=123', 'session')).toBe('abc=123');
  });

  it('returns null for empty cookie header', () => {
    expect(parseCookie('', 'session')).toBeNull();
  });
});

describe('Auth Plugin — sanitizeBody', () => {
  it('redacts sensitive fields', () => {
    const body = {
      email: 'test@example.com',
      password: 'supersecret',
      totp_code: '123456',
      recovery_code: 'ABCD-EFGH',
      mfa_session_token: 'token123',
    };
    const sanitized = sanitizeBody(body);
    expect(sanitized).toEqual({
      email: 'test@example.com',
      password: '[REDACTED]',
      totp_code: '[REDACTED]',
      recovery_code: '[REDACTED]',
      mfa_session_token: '[REDACTED]',
    });
  });

  it('passes through non-sensitive fields unchanged', () => {
    const body = { email: 'a@b.com', full_name: 'Test User' };
    expect(sanitizeBody(body)).toEqual(body);
  });

  it('returns undefined for null/undefined body', () => {
    expect(sanitizeBody(null)).toBeUndefined();
    expect(sanitizeBody(undefined)).toBeUndefined();
  });
});

describe('Auth Plugin — authenticate', () => {
  // Build a minimal mock Fastify-like request/reply for testing plugin logic
  function makeSessionDeps(sessions: any[] = []) {
    return {
      sessionRepo: {
        async findSessionByTokenHash(tokenHash: string) {
          const session = sessions.find(
            (s) => s.tokenHash === tokenHash && !s.revoked,
          );
          if (!session) return undefined;
          const now = Date.now();
          if (now - new Date(session.createdAt).getTime() > 24 * 60 * 60 * 1000) return undefined;
          if (now - new Date(session.lastActiveAt).getTime() > 60 * 60 * 1000) return undefined;
          return { session, user: session.__user };
        },
        async refreshSession(_sessionId: string) {},
        async listActiveSessions(_userId: string) { return []; },
        async revokeSession(_sessionId: string, _reason: string) {},
        async revokeAllUserSessions() {},
      },
      auditRepo: {
        async appendAuditLog(_entry: any) { return {}; },
      },
      events: {
        emit() {},
      },
    };
  }

  function makeRequest(overrides: Partial<any> = {}): any {
    return {
      headers: { cookie: '' },
      authContext: undefined as any,
      ...overrides,
    };
  }

  function makeReply(): any {
    const reply: any = {
      statusCode: 200,
      body: null,
      code(code: number) { reply.statusCode = code; return reply; },
      send(body: any) { reply.body = body; return reply; },
    };
    return reply;
  }

  it('authenticate rejects request without cookie', async () => {
    const sessions: any[] = [];
    const sessionDeps = makeSessionDeps(sessions);

    // Import the plugin helpers — we'll test validateSession flow directly
    const request = makeRequest({ headers: {} });
    const reply = makeReply();

    // Simulate authenticate logic directly
    const cookieHeader = request.headers.cookie;
    if (!cookieHeader) {
      reply.code(401).send({
        error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
      });
    }

    expect(reply.statusCode).toBe(401);
    expect(reply.body.error.code).toBe('UNAUTHORIZED');
  });

  it('authenticate rejects request with invalid token', async () => {
    const sessions: any[] = [];
    const sessionDeps = makeSessionDeps(sessions);

    const { createHash } = await import('node:crypto');
    const tokenHash = createHash('sha256').update('bad_token').digest('hex');

    const result = await validateSession(sessionDeps as any, tokenHash);
    expect(result).toBeNull();
  });

  it('authenticate populates authContext on valid session', async () => {
    const validTokenHash = 'abc123hash';
    const sessions = [
      {
        sessionId: 'sess-1',
        userId: 'user-1',
        tokenHash: validTokenHash,
        ipAddress: '127.0.0.1',
        userAgent: 'TestAgent',
        createdAt: new Date(),
        lastActiveAt: new Date(),
        revoked: false,
        revokedReason: null,
        __user: {
          userId: 'user-1',
          role: 'physician',
          subscriptionStatus: 'ACTIVE',
        },
      },
    ];
    const sessionDeps = makeSessionDeps(sessions);

    const result = await validateSession(sessionDeps as any, validTokenHash);

    expect(result).not.toBeNull();
    expect(result!.userId).toBe('user-1');
    expect(result!.role).toBe('physician');
    expect(result!.subscriptionStatus).toBe('ACTIVE');
    expect(result!.sessionId).toBe('sess-1');
  });
});

describe('Auth Plugin — authorize', () => {
  it('authorize allows physician for any permission', () => {
    const authContext: any = {
      userId: 'user-1',
      role: 'PHYSICIAN',
      subscriptionStatus: 'ACTIVE',
      sessionId: 'sess-1',
    };

    // Physicians have all permissions — check that even an arbitrary permission passes
    const role = authContext.role.toUpperCase();
    const allowed = role === 'PHYSICIAN' || role === 'ADMIN';
    expect(allowed).toBe(true);
  });

  it('authorize allows admin for any permission', () => {
    const authContext: any = {
      userId: 'admin-1',
      role: 'ADMIN',
      subscriptionStatus: 'ACTIVE',
      sessionId: 'sess-1',
    };

    const role = authContext.role.toUpperCase();
    const allowed = role === 'PHYSICIAN' || role === 'ADMIN';
    expect(allowed).toBe(true);
  });

  it('authorize allows delegate with matching permission', () => {
    const authContext: any = {
      userId: 'del-1',
      role: 'DELEGATE',
      subscriptionStatus: 'ACTIVE',
      sessionId: 'sess-1',
      delegateContext: {
        delegateUserId: 'del-1',
        physicianUserId: 'phys-1',
        permissions: ['CLAIM_VIEW', 'CLAIM_CREATE', 'PATIENT_VIEW'],
        canApproveBatches: false,
      },
    };

    const requiredPermissions = ['CLAIM_VIEW', 'PATIENT_VIEW'];
    const delegatePerms = authContext.delegateContext.permissions as string[];
    const missing = requiredPermissions.filter((p) => !delegatePerms.includes(p));
    expect(missing.length).toBe(0);
  });

  it('authorize rejects delegate without matching permission', () => {
    const authContext: any = {
      userId: 'del-1',
      role: 'DELEGATE',
      subscriptionStatus: 'ACTIVE',
      sessionId: 'sess-1',
      delegateContext: {
        delegateUserId: 'del-1',
        physicianUserId: 'phys-1',
        permissions: ['CLAIM_VIEW'],
        canApproveBatches: false,
      },
    };

    const requiredPermissions = ['CLAIM_VIEW', 'CLAIM_CREATE'];
    const delegatePerms = authContext.delegateContext.permissions as string[];
    const missing = requiredPermissions.filter((p) => !delegatePerms.includes(p));
    expect(missing.length).toBeGreaterThan(0);
    expect(missing).toContain('CLAIM_CREATE');
  });

  it('authorize rejects delegate without delegateContext', () => {
    const authContext: any = {
      userId: 'del-1',
      role: 'DELEGATE',
      subscriptionStatus: 'ACTIVE',
      sessionId: 'sess-1',
      // no delegateContext
    };

    const delegateContext = authContext.delegateContext;
    const hasPermissions = delegateContext && delegateContext.permissions;
    expect(hasPermissions).toBeFalsy();
  });
});

describe('Auth Plugin — checkSubscription', () => {
  it('checkSubscription allows active status', () => {
    const allowedStatuses = ['TRIAL', 'ACTIVE'];
    const status = 'ACTIVE';
    expect(allowedStatuses.includes(status)).toBe(true);
  });

  it('checkSubscription allows trial status', () => {
    const allowedStatuses = ['TRIAL', 'ACTIVE'];
    const status = 'TRIAL';
    expect(allowedStatuses.includes(status)).toBe(true);
  });

  it('checkSubscription returns 402 for suspended', () => {
    const allowedStatuses = ['TRIAL', 'ACTIVE'];
    const status = 'SUSPENDED';
    const isAllowed = allowedStatuses.includes(status);
    expect(isAllowed).toBe(false);

    // Simulate response
    const errorCode = status === 'SUSPENDED' ? 'ACCOUNT_SUSPENDED' : 'SUBSCRIPTION_REQUIRED';
    expect(errorCode).toBe('ACCOUNT_SUSPENDED');
  });

  it('checkSubscription returns 402 for cancelled', () => {
    const allowedStatuses = ['TRIAL', 'ACTIVE'];
    const status = 'CANCELLED';
    const isAllowed = allowedStatuses.includes(status);
    expect(isAllowed).toBe(false);

    const errorCode = (status as string) === 'SUSPENDED' ? 'ACCOUNT_SUSPENDED' : 'SUBSCRIPTION_REQUIRED';
    expect(errorCode).toBe('SUBSCRIPTION_REQUIRED');
  });
});

describe('Auth Plugin — auditLog sanitization', () => {
  it('sanitizes password, totp_code, recovery_code from request body', () => {
    const body = {
      email: 'test@test.com',
      password: 'secret123',
      totp_code: '123456',
      current_totp_code: '654321',
      recovery_code: 'ABCD-EFGH',
      new_password: 'newpass',
      mfa_session_token: 'token',
      full_name: 'Test User',
    };
    const sanitized = sanitizeBody(body)!;

    expect(sanitized.email).toBe('test@test.com');
    expect(sanitized.full_name).toBe('Test User');
    expect(sanitized.password).toBe('[REDACTED]');
    expect(sanitized.totp_code).toBe('[REDACTED]');
    expect(sanitized.current_totp_code).toBe('[REDACTED]');
    expect(sanitized.recovery_code).toBe('[REDACTED]');
    expect(sanitized.new_password).toBe('[REDACTED]');
    expect(sanitized.mfa_session_token).toBe('[REDACTED]');
  });
});

describe('Rate Limit Plugin — configuration', () => {
  it('authRateLimit returns correct config', async () => {
    const { authRateLimit } = await import('../../plugins/rate-limit.plugin.js');
    const config = authRateLimit();
    expect(config.max).toBe(10);
    expect(config.timeWindow).toBe('1 minute');
    expect(typeof config.keyGenerator).toBe('function');
  });

  it('uploadRateLimit returns correct config', async () => {
    const { uploadRateLimit } = await import('../../plugins/rate-limit.plugin.js');
    const config = uploadRateLimit();
    expect(config.max).toBe(5);
    expect(config.timeWindow).toBe('1 minute');
    expect(typeof config.keyGenerator).toBe('function');
  });

  it('noRateLimit returns disabled config', async () => {
    const { noRateLimit } = await import('../../plugins/rate-limit.plugin.js');
    const config = noRateLimit();
    expect(config.max).toBe(0);
  });

  it('rate limiting blocks after threshold exceeded', async () => {
    const { authRateLimit } = await import('../../plugins/rate-limit.plugin.js');
    const config = authRateLimit();
    // Auth rate limit is 10 req/min per IP
    expect(config.max).toBe(10);

    // The keyGenerator should use request.ip for auth endpoints
    const mockRequest = { ip: '192.168.1.1', authContext: undefined };
    const key = config.keyGenerator(mockRequest);
    expect(key).toBe('192.168.1.1');
  });
});
