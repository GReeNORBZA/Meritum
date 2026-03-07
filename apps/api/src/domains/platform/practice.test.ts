import crypto from 'node:crypto';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createPracticeRepository } from './practice.repository.js';
import {
  createPractice,
  invitePhysician,
  acceptInvitation,
  removePhysician,
  handleEndOfMonthRemovals,
  getPracticeSeats,
  getPracticeInvoice,
  type PracticeServiceDeps,
  type PracticeUserRepo,
  type PracticeSubscriptionRepo,
  type PracticeStripeClient,
  type PracticeAuditLogger,
  type PracticeNotifier,
  type PracticeSeat,
  type PracticeInvoiceInfo,
} from './practice.service.js';
import { createPracticeHandlers, type PracticeHandlerDeps } from './practice.handlers.js';

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

let practiceStore: Record<string, any>[];
let membershipStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Mock Drizzle DB
// ---------------------------------------------------------------------------

function makeMockDb() {
  function getStoreForTable(table: any): Record<string, any>[] {
    if (table?.__table === 'practices') return practiceStore;
    if (table?.__table === 'practice_memberships') return membershipStore;
    return practiceStore;
  }

  function chainable(ctx: {
    op: string;
    table?: any;
    values?: any;
    setClauses?: any;
    selectFields?: any;
    whereClauses: Array<(row: any) => boolean>;
    limitN?: number;
  }) {
    const chain: any = {
      _ctx: ctx,
      values(v: any) { ctx.values = v; return chain; },
      set(s: any) { ctx.setClauses = s; return chain; },
      from(table: any) { ctx.table = table; return chain; },
      where(clause: any) {
        if (typeof clause === 'function') {
          ctx.whereClauses.push(clause);
        } else if (clause && typeof clause === 'object' && clause.__predicate) {
          ctx.whereClauses.push(clause.__predicate);
        }
        return chain;
      },
      limit(n: number) { ctx.limitN = n; return chain; },
      returning() { return chain; },
      then(resolve: any, reject?: any) {
        try {
          resolve(executeOp(ctx));
        } catch (e) {
          if (reject) reject(e); else throw e;
        }
      },
    };
    return chain;
  }

  function insertRow(table: any, values: any): any {
    const store = getStoreForTable(table);

    if (table?.__table === 'practices') {
      const newPractice = {
        practiceId: values.practiceId ?? crypto.randomUUID(),
        name: values.name,
        adminUserId: values.adminUserId,
        stripeCustomerId: values.stripeCustomerId ?? null,
        stripeSubscriptionId: values.stripeSubscriptionId ?? null,
        billingFrequency: values.billingFrequency,
        status: values.status ?? 'ACTIVE',
        currentPeriodStart: values.currentPeriodStart,
        currentPeriodEnd: values.currentPeriodEnd,
        createdAt: values.createdAt ?? new Date(),
        updatedAt: values.updatedAt ?? new Date(),
      };
      store.push(newPractice);
      return newPractice;
    }

    if (table?.__table === 'practice_memberships') {
      const newMembership = {
        membershipId: values.membershipId ?? crypto.randomUUID(),
        practiceId: values.practiceId,
        physicianUserId: values.physicianUserId,
        billingMode: values.billingMode ?? 'PRACTICE_CONSOLIDATED',
        joinedAt: values.joinedAt ?? new Date(),
        removedAt: values.removedAt ?? null,
        removalEffectiveAt: values.removalEffectiveAt ?? null,
        isActive: values.isActive ?? true,
        createdAt: values.createdAt ?? new Date(),
      };
      store.push(newMembership);
      return newMembership;
    }

    store.push({ ...values });
    return values;
  }

  function executeOp(ctx: any): any[] {
    switch (ctx.op) {
      case 'select': {
        const store = getStoreForTable(ctx.table);
        let matches = store.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );

        // Handle aggregate select fields
        if (ctx.selectFields) {
          const fields = ctx.selectFields;
          const hasAggregates = Object.values(fields).some(
            (f: any) => f?.__aggregate,
          );
          if (hasAggregates) {
            const result: Record<string, any> = {};
            for (const [key, spec] of Object.entries(fields) as [string, any][]) {
              if (!spec?.__aggregate) {
                result[key] = matches[0]?.[spec?.name] ?? null;
                continue;
              }
              switch (spec.__aggregate) {
                case 'count':
                  result[key] = matches.length;
                  break;
              }
            }
            return [result];
          }
        }

        return ctx.limitN ? matches.slice(0, ctx.limitN) : matches;
      }
      case 'insert': {
        const values = ctx.values;
        if (Array.isArray(values)) {
          return values.map((v: any) => insertRow(ctx.table, v));
        }
        return [insertRow(ctx.table, values)];
      }
      case 'update': {
        const updated: any[] = [];
        const store = getStoreForTable(ctx.table);
        const matches = store.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );
        for (const row of matches) {
          const setClauses = ctx.setClauses;
          if (!setClauses) continue;
          for (const [key, value] of Object.entries(setClauses)) {
            row[key] = value;
          }
          updated.push({ ...row });
        }
        return updated;
      }
      default:
        return [];
    }
  }

  const mockDb: any = {
    insert(table: any) {
      return chainable({ op: 'insert', table, whereClauses: [] });
    },
    select(fields?: any) {
      return chainable({ op: 'select', selectFields: fields, whereClauses: [] });
    },
    update(table: any) {
      return chainable({ op: 'update', table, whereClauses: [] });
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
      };
    },
    and: (...conditions: any[]) => {
      const preds = conditions.filter(Boolean);
      return {
        __predicate: (row: any) =>
          preds.every((p: any) => {
            if (p?.__predicate) return p.__predicate(row);
            return true;
          }),
      };
    },
    lte: (column: any, value: any) => {
      const colName = column?.name;
      return {
        __predicate: (row: any) => row[colName] <= value,
      };
    },
    sql: () => ({}),
    count: () => ({ __aggregate: 'count' }),
  };
});

// Mock the constants modules — required because vitest module resolution
// through the @meritum/shared alias can fail for transitive imports
vi.mock('@meritum/shared/constants/platform.constants.js', async () => {
  return {
    BillingMode: {
      PRACTICE_CONSOLIDATED: 'PRACTICE_CONSOLIDATED',
      INDIVIDUAL_EARLY_BIRD: 'INDIVIDUAL_EARLY_BIRD',
    },
    PracticeStatus: {
      ACTIVE: 'ACTIVE',
      SUSPENDED: 'SUSPENDED',
      CANCELLED: 'CANCELLED',
    },
    PracticeInvitationStatus: {
      PENDING: 'PENDING',
      ACCEPTED: 'ACCEPTED',
      DECLINED: 'DECLINED',
      EXPIRED: 'EXPIRED',
    },
    SubscriptionPlan: {
      STANDARD_MONTHLY: 'STANDARD_MONTHLY',
      STANDARD_ANNUAL: 'STANDARD_ANNUAL',
      EARLY_BIRD_MONTHLY: 'EARLY_BIRD_MONTHLY',
      EARLY_BIRD_ANNUAL: 'EARLY_BIRD_ANNUAL',
      CLINIC_MONTHLY: 'CLINIC_MONTHLY',
      CLINIC_ANNUAL: 'CLINIC_ANNUAL',
    },
    PRACTICE_INVITATION_EXPIRY_DAYS: 7,
    CLINIC_MINIMUM_PHYSICIANS: 5,
    DISCOUNT_ANNUAL: 0.05,
    DISCOUNT_CLINIC: 0.10,
    DISCOUNT_CEILING: 0.15,
    GST_RATE: 0.05,
    SubscriptionPlanPricing: {
      CLINIC_MONTHLY: {
        plan: 'CLINIC_MONTHLY',
        amount: '251.10',
        interval: 'month',
        label: 'Clinic Monthly',
      },
      CLINIC_ANNUAL: {
        plan: 'CLINIC_ANNUAL',
        amount: '2863.00',
        interval: 'year',
        label: 'Clinic Annual',
      },
    },
  };
});

vi.mock('@meritum/shared/constants/iam.constants.js', async () => {
  return {
    Role: {
      PHYSICIAN: 'PHYSICIAN',
      DELEGATE: 'DELEGATE',
      ADMIN: 'ADMIN',
      PRACTICE_ADMIN: 'PRACTICE_ADMIN',
    },
    SubscriptionStatus: {
      TRIAL: 'TRIAL',
      ACTIVE: 'ACTIVE',
      PAST_DUE: 'PAST_DUE',
      SUSPENDED: 'SUSPENDED',
      CANCELLED: 'CANCELLED',
    },
  };
});

// Mock the schema module
vi.mock('@meritum/shared/schemas/db/platform.schema.js', () => {
  const makeCol = (name: string) => ({ name });

  const practicesProxy: any = {
    __table: 'practices',
    practiceId: makeCol('practiceId'),
    name: makeCol('name'),
    adminUserId: makeCol('adminUserId'),
    stripeCustomerId: makeCol('stripeCustomerId'),
    stripeSubscriptionId: makeCol('stripeSubscriptionId'),
    billingFrequency: makeCol('billingFrequency'),
    status: makeCol('status'),
    currentPeriodStart: makeCol('currentPeriodStart'),
    currentPeriodEnd: makeCol('currentPeriodEnd'),
    createdAt: makeCol('createdAt'),
    updatedAt: makeCol('updatedAt'),
  };

  const practiceMembershipsProxy: any = {
    __table: 'practice_memberships',
    membershipId: makeCol('membershipId'),
    practiceId: makeCol('practiceId'),
    physicianUserId: makeCol('physicianUserId'),
    billingMode: makeCol('billingMode'),
    joinedAt: makeCol('joinedAt'),
    removedAt: makeCol('removedAt'),
    removalEffectiveAt: makeCol('removalEffectiveAt'),
    isActive: makeCol('isActive'),
    createdAt: makeCol('createdAt'),
  };

  const practiceInvitationsProxy: any = {
    __table: 'practice_invitations',
    invitationId: makeCol('invitationId'),
    practiceId: makeCol('practiceId'),
    invitedEmail: makeCol('invitedEmail'),
    invitedByUserId: makeCol('invitedByUserId'),
    status: makeCol('status'),
    tokenHash: makeCol('tokenHash'),
    expiresAt: makeCol('expiresAt'),
    createdAt: makeCol('createdAt'),
  };

  return {
    practices: practicesProxy,
    practiceMemberships: practiceMembershipsProxy,
    practiceInvitations: practiceInvitationsProxy,
  };
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DAY_MS = 24 * 60 * 60 * 1000;

function makePractice(overrides: Partial<Record<string, any>> = {}) {
  return {
    name: overrides.name ?? 'Test Medical Clinic',
    adminUserId: overrides.adminUserId ?? crypto.randomUUID(),
    stripeCustomerId: overrides.stripeCustomerId ?? null,
    stripeSubscriptionId: overrides.stripeSubscriptionId ?? null,
    billingFrequency: overrides.billingFrequency ?? 'MONTHLY',
    status: overrides.status ?? 'ACTIVE',
    currentPeriodStart: overrides.currentPeriodStart ?? new Date(),
    currentPeriodEnd: overrides.currentPeriodEnd ?? new Date(Date.now() + 30 * DAY_MS),
    createdAt: overrides.createdAt ?? new Date(),
    updatedAt: overrides.updatedAt ?? new Date(),
  };
}

function makeMembership(overrides: Partial<Record<string, any>> = {}) {
  return {
    practiceId: overrides.practiceId ?? crypto.randomUUID(),
    physicianUserId: overrides.physicianUserId ?? crypto.randomUUID(),
    billingMode: overrides.billingMode ?? 'PRACTICE_CONSOLIDATED',
    isActive: overrides.isActive ?? true,
    joinedAt: overrides.joinedAt ?? new Date(),
    removedAt: overrides.removedAt ?? null,
    removalEffectiveAt: overrides.removalEffectiveAt ?? null,
    createdAt: overrides.createdAt ?? new Date(),
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('PracticeRepository', () => {
  let repo: ReturnType<typeof createPracticeRepository>;
  let db: any;

  beforeEach(() => {
    practiceStore = [];
    membershipStore = [];
    db = makeMockDb();
    repo = createPracticeRepository(db);
  });

  // -------------------------------------------------------------------------
  // createPractice
  // -------------------------------------------------------------------------

  it('createPractice inserts a practice and returns the record', async () => {
    const data = makePractice();
    const result = await repo.createPractice(data as any);

    expect(result).toBeDefined();
    expect(result.practiceId).toBeDefined();
    expect(result.name).toBe('Test Medical Clinic');
    expect(result.adminUserId).toBe(data.adminUserId);
    expect(result.billingFrequency).toBe('MONTHLY');
    expect(result.status).toBe('ACTIVE');
    expect(result.stripeCustomerId).toBeNull();
    expect(result.stripeSubscriptionId).toBeNull();
    expect(practiceStore).toHaveLength(1);
  });

  // -------------------------------------------------------------------------
  // findPracticeById
  // -------------------------------------------------------------------------

  it('findPracticeById returns the correct practice', async () => {
    const data = makePractice();
    const created = await repo.createPractice(data as any);

    const found = await repo.findPracticeById(created.practiceId);
    expect(found).toBeDefined();
    expect(found!.practiceId).toBe(created.practiceId);
    expect(found!.name).toBe('Test Medical Clinic');
  });

  it('findPracticeById returns null for non-existent ID', async () => {
    const found = await repo.findPracticeById(crypto.randomUUID());
    expect(found).toBeNull();
  });

  // -------------------------------------------------------------------------
  // findPracticeByAdminUserId
  // -------------------------------------------------------------------------

  it('findPracticeByAdminUserId returns the admin active practice', async () => {
    const adminUserId = crypto.randomUUID();
    const data = makePractice({ adminUserId });
    await repo.createPractice(data as any);

    const found = await repo.findPracticeByAdminUserId(adminUserId);
    expect(found).toBeDefined();
    expect(found!.adminUserId).toBe(adminUserId);
    expect(found!.status).toBe('ACTIVE');
  });

  it('findPracticeByAdminUserId returns null for non-admin user', async () => {
    const adminUserId = crypto.randomUUID();
    const otherUserId = crypto.randomUUID();
    const data = makePractice({ adminUserId });
    await repo.createPractice(data as any);

    const found = await repo.findPracticeByAdminUserId(otherUserId);
    expect(found).toBeNull();
  });

  it('findPracticeByAdminUserId returns null for suspended practice', async () => {
    const adminUserId = crypto.randomUUID();
    const data = makePractice({ adminUserId, status: 'SUSPENDED' });
    await repo.createPractice(data as any);

    const found = await repo.findPracticeByAdminUserId(adminUserId);
    expect(found).toBeNull();
  });

  // -------------------------------------------------------------------------
  // updatePractice
  // -------------------------------------------------------------------------

  it('updatePractice updates name and sets updated_at', async () => {
    const data = makePractice();
    const created = await repo.createPractice(data as any);
    const beforeUpdate = new Date();

    const updated = await repo.updatePractice(created.practiceId, {
      name: 'New Clinic Name',
    } as any);

    expect(updated).toBeDefined();
    expect(updated.name).toBe('New Clinic Name');
    expect(updated.updatedAt).toBeDefined();
    expect(updated.updatedAt.getTime()).toBeGreaterThanOrEqual(
      beforeUpdate.getTime(),
    );
  });

  // -------------------------------------------------------------------------
  // updatePracticeStatus
  // -------------------------------------------------------------------------

  it('updatePracticeStatus changes status correctly', async () => {
    const data = makePractice();
    const created = await repo.createPractice(data as any);

    await repo.updatePracticeStatus(created.practiceId, 'SUSPENDED');

    // Verify in store
    const stored = practiceStore.find(
      (p) => p.practiceId === created.practiceId,
    );
    expect(stored!.status).toBe('SUSPENDED');
    expect(stored!.updatedAt).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // updatePracticeStripeIds
  // -------------------------------------------------------------------------

  it('updatePracticeStripeIds sets both Stripe IDs', async () => {
    const data = makePractice();
    const created = await repo.createPractice(data as any);

    await repo.updatePracticeStripeIds(
      created.practiceId,
      'cus_practice_123',
      'sub_practice_456',
    );

    const stored = practiceStore.find(
      (p) => p.practiceId === created.practiceId,
    );
    expect(stored!.stripeCustomerId).toBe('cus_practice_123');
    expect(stored!.stripeSubscriptionId).toBe('sub_practice_456');
    expect(stored!.updatedAt).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // getActiveHeadcount
  // -------------------------------------------------------------------------

  it('getActiveHeadcount counts all active members regardless of billing mode', async () => {
    const data = makePractice();
    const created = await repo.createPractice(data as any);
    const practiceId = created.practiceId;

    // Add members directly to the store — both billing modes
    membershipStore.push(
      {
        membershipId: crypto.randomUUID(),
        practiceId,
        physicianUserId: crypto.randomUUID(),
        billingMode: 'PRACTICE_CONSOLIDATED',
        isActive: true,
        joinedAt: new Date(),
        createdAt: new Date(),
      },
      {
        membershipId: crypto.randomUUID(),
        practiceId,
        physicianUserId: crypto.randomUUID(),
        billingMode: 'PRACTICE_CONSOLIDATED',
        isActive: true,
        joinedAt: new Date(),
        createdAt: new Date(),
      },
      {
        membershipId: crypto.randomUUID(),
        practiceId,
        physicianUserId: crypto.randomUUID(),
        billingMode: 'INDIVIDUAL_EARLY_BIRD',
        isActive: true,
        joinedAt: new Date(),
        createdAt: new Date(),
      },
    );

    const headcount = await repo.getActiveHeadcount(practiceId);
    expect(headcount).toBe(3);
  });

  it('getActiveHeadcount excludes inactive members', async () => {
    const data = makePractice();
    const created = await repo.createPractice(data as any);
    const practiceId = created.practiceId;

    membershipStore.push(
      {
        membershipId: crypto.randomUUID(),
        practiceId,
        physicianUserId: crypto.randomUUID(),
        billingMode: 'PRACTICE_CONSOLIDATED',
        isActive: true,
        joinedAt: new Date(),
        createdAt: new Date(),
      },
      {
        membershipId: crypto.randomUUID(),
        practiceId,
        physicianUserId: crypto.randomUUID(),
        billingMode: 'PRACTICE_CONSOLIDATED',
        isActive: false, // inactive
        joinedAt: new Date(),
        createdAt: new Date(),
      },
    );

    const headcount = await repo.getActiveHeadcount(practiceId);
    expect(headcount).toBe(1);
  });

  // -------------------------------------------------------------------------
  // getConsolidatedSeatCount
  // -------------------------------------------------------------------------

  it('getConsolidatedSeatCount counts only PRACTICE_CONSOLIDATED members', async () => {
    const data = makePractice();
    const created = await repo.createPractice(data as any);
    const practiceId = created.practiceId;

    membershipStore.push(
      {
        membershipId: crypto.randomUUID(),
        practiceId,
        physicianUserId: crypto.randomUUID(),
        billingMode: 'PRACTICE_CONSOLIDATED',
        isActive: true,
        joinedAt: new Date(),
        createdAt: new Date(),
      },
      {
        membershipId: crypto.randomUUID(),
        practiceId,
        physicianUserId: crypto.randomUUID(),
        billingMode: 'PRACTICE_CONSOLIDATED',
        isActive: true,
        joinedAt: new Date(),
        createdAt: new Date(),
      },
      {
        membershipId: crypto.randomUUID(),
        practiceId,
        physicianUserId: crypto.randomUUID(),
        billingMode: 'INDIVIDUAL_EARLY_BIRD',
        isActive: true,
        joinedAt: new Date(),
        createdAt: new Date(),
      },
    );

    const seatCount = await repo.getConsolidatedSeatCount(practiceId);
    expect(seatCount).toBe(2);
  });

  it('getConsolidatedSeatCount excludes INDIVIDUAL_EARLY_BIRD members', async () => {
    const data = makePractice();
    const created = await repo.createPractice(data as any);
    const practiceId = created.practiceId;

    // Only early bird members
    membershipStore.push(
      {
        membershipId: crypto.randomUUID(),
        practiceId,
        physicianUserId: crypto.randomUUID(),
        billingMode: 'INDIVIDUAL_EARLY_BIRD',
        isActive: true,
        joinedAt: new Date(),
        createdAt: new Date(),
      },
      {
        membershipId: crypto.randomUUID(),
        practiceId,
        physicianUserId: crypto.randomUUID(),
        billingMode: 'INDIVIDUAL_EARLY_BIRD',
        isActive: true,
        joinedAt: new Date(),
        createdAt: new Date(),
      },
    );

    const seatCount = await repo.getConsolidatedSeatCount(practiceId);
    expect(seatCount).toBe(0);
  });

  // -------------------------------------------------------------------------
  // findActivePractices
  // -------------------------------------------------------------------------

  it('findActivePractices returns only ACTIVE status practices', async () => {
    await repo.createPractice(
      makePractice({ name: 'Active Clinic', status: 'ACTIVE' }) as any,
    );
    await repo.createPractice(
      makePractice({ name: 'Suspended Clinic', status: 'SUSPENDED' }) as any,
    );
    await repo.createPractice(
      makePractice({ name: 'Another Active', status: 'ACTIVE' }) as any,
    );

    const actives = await repo.findActivePractices();
    expect(actives).toHaveLength(2);
    for (const p of actives) {
      expect(p.status).toBe('ACTIVE');
    }
  });
});

// ===========================================================================
// Practice Service — createPractice
// ===========================================================================

describe('createPractice', () => {
  const adminUserId = crypto.randomUUID();
  const practiceName = 'Alpine Family Clinic';
  let deps: PracticeServiceDeps;
  let mockPracticeRepo: any;
  let mockMembershipRepo: any;
  let mockUserRepo: PracticeUserRepo;
  let mockSubscriptionRepo: PracticeSubscriptionRepo;
  let mockStripe: PracticeStripeClient;
  let mockAuditLogger: PracticeAuditLogger;
  let roleUpdates: Array<{ userId: string; role: string }>;
  let createdMemberships: any[];
  let createdPractices: any[];
  let updatedPractices: any[];
  let auditLogs: any[];
  let stripeCustomersCreated: any[];

  beforeEach(() => {
    roleUpdates = [];
    createdMemberships = [];
    createdPractices = [];
    updatedPractices = [];
    auditLogs = [];
    stripeCustomersCreated = [];

    mockUserRepo = {
      findUserById: vi.fn().mockResolvedValue({
        userId: adminUserId,
        email: 'dr.smith@example.com',
        fullName: 'Dr. Smith',
        role: 'PHYSICIAN',
      }),
      findUserByEmail: vi.fn().mockResolvedValue(undefined),
      updateUserRole: vi.fn().mockImplementation(async (userId, role) => {
        roleUpdates.push({ userId, role });
      }),
    };

    mockSubscriptionRepo = {
      findActiveEarlyBirdByProviderId: vi.fn().mockResolvedValue(null),
    };

    mockPracticeRepo = {
      findPracticeByAdminUserId: vi.fn().mockResolvedValue(null),
      createPractice: vi.fn().mockImplementation(async (data: any) => {
        const practice = {
          practiceId: crypto.randomUUID(),
          name: data.name,
          adminUserId: data.adminUserId,
          stripeCustomerId: data.stripeCustomerId ?? null,
          stripeSubscriptionId: data.stripeSubscriptionId ?? null,
          billingFrequency: data.billingFrequency,
          status: data.status ?? 'ACTIVE',
          currentPeriodStart: data.currentPeriodStart,
          currentPeriodEnd: data.currentPeriodEnd,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        createdPractices.push(practice);
        return practice;
      }),
      updatePractice: vi.fn().mockImplementation(async (practiceId: string, data: any) => {
        const practice = createdPractices.find((p) => p.practiceId === practiceId);
        const updated = { ...practice, ...data, updatedAt: new Date() };
        updatedPractices.push(updated);
        return updated;
      }),
    };

    mockMembershipRepo = {
      findActiveMembershipByPhysicianId: vi.fn().mockResolvedValue(null),
      createMembership: vi.fn().mockImplementation(async (data: any) => {
        const membership = {
          membershipId: crypto.randomUUID(),
          practiceId: data.practiceId,
          physicianUserId: data.physicianUserId,
          billingMode: data.billingMode ?? 'PRACTICE_CONSOLIDATED',
          joinedAt: data.joinedAt ?? new Date(),
          removedAt: null,
          removalEffectiveAt: null,
          isActive: true,
          createdAt: new Date(),
        };
        createdMemberships.push(membership);
        return membership;
      }),
    };

    mockStripe = {
      customers: {
        create: vi.fn().mockImplementation(async (params: any) => {
          const customer = { id: `cus_${crypto.randomUUID().slice(0, 14)}` };
          stripeCustomersCreated.push({ ...params, result: customer });
          return customer;
        }),
      },
    };

    mockAuditLogger = {
      log: vi.fn().mockImplementation(async (entry: any) => {
        auditLogs.push(entry);
      }),
    };

    deps = {
      practiceRepo: mockPracticeRepo,
      membershipRepo: mockMembershipRepo,
      invitationRepo: {} as any,
      userRepo: mockUserRepo,
      subscriptionRepo: mockSubscriptionRepo,
      stripe: mockStripe,
      auditLogger: mockAuditLogger,
    };
  });

  // -------------------------------------------------------------------------
  // Happy path
  // -------------------------------------------------------------------------

  it('creates a practice with correct name and billing frequency', async () => {
    const result = await createPractice(deps, adminUserId, practiceName, 'MONTHLY');

    expect(result).toBeDefined();
    expect(result.name).toBe(practiceName);
    expect(result.billingFrequency).toBe('MONTHLY');
    expect(result.status).toBe('ACTIVE');
    expect(result.adminUserId).toBe(adminUserId);
  });

  it('creates a membership for the admin with correct billing_mode', async () => {
    await createPractice(deps, adminUserId, practiceName, 'MONTHLY');

    expect(createdMemberships).toHaveLength(1);
    const membership = createdMemberships[0];
    expect(membership.physicianUserId).toBe(adminUserId);
    expect(membership.billingMode).toBe('PRACTICE_CONSOLIDATED');
    expect(membership.joinedAt).toBeInstanceOf(Date);
  });

  it('assigns PRACTICE_ADMIN role to admin user', async () => {
    await createPractice(deps, adminUserId, practiceName, 'MONTHLY');

    expect(roleUpdates).toHaveLength(1);
    expect(roleUpdates[0].userId).toBe(adminUserId);
    expect(roleUpdates[0].role).toBe('PRACTICE_ADMIN');
  });

  it('creates a Stripe customer with practice name and admin email', async () => {
    await createPractice(deps, adminUserId, practiceName, 'MONTHLY');

    expect(stripeCustomersCreated).toHaveLength(1);
    const stripeCall = stripeCustomersCreated[0];
    expect(stripeCall.name).toBe(practiceName);
    expect(stripeCall.email).toBe('dr.smith@example.com');
    expect(stripeCall.metadata.practice_id).toBeDefined();
    // Verify NO PHI in Stripe call
    expect(JSON.stringify(stripeCall)).not.toContain('PHN');
    expect(JSON.stringify(stripeCall)).not.toContain('patient');
  });

  it('updates practice with Stripe customer ID', async () => {
    const result = await createPractice(deps, adminUserId, practiceName, 'MONTHLY');

    expect(result.stripeCustomerId).toBeDefined();
    expect(result.stripeCustomerId).toMatch(/^cus_/);
    expect(mockPracticeRepo.updatePractice).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        stripeCustomerId: expect.stringMatching(/^cus_/),
      }),
    );
  });

  // -------------------------------------------------------------------------
  // Validation errors
  // -------------------------------------------------------------------------

  it('rejects if user is not a physician', async () => {
    (mockUserRepo.findUserById as any).mockResolvedValue({
      userId: adminUserId,
      email: 'delegate@example.com',
      fullName: 'A Delegate',
      role: 'DELEGATE',
    });

    await expect(
      createPractice(deps, adminUserId, practiceName, 'MONTHLY'),
    ).rejects.toThrow('Only physicians can create a practice');

    // Verify error has code
    try {
      await createPractice(deps, adminUserId, practiceName, 'MONTHLY');
    } catch (err: any) {
      expect(err.details).toEqual({ code: 'NOT_A_PHYSICIAN' });
    }
  });

  it('rejects if user does not exist', async () => {
    (mockUserRepo.findUserById as any).mockResolvedValue(undefined);

    await expect(
      createPractice(deps, adminUserId, practiceName, 'MONTHLY'),
    ).rejects.toThrow('User not found');
  });

  it('rejects if user already admins a practice', async () => {
    mockPracticeRepo.findPracticeByAdminUserId.mockResolvedValue({
      practiceId: crypto.randomUUID(),
      adminUserId,
      status: 'ACTIVE',
    });

    await expect(
      createPractice(deps, adminUserId, practiceName, 'MONTHLY'),
    ).rejects.toThrow('User already administers a practice');

    try {
      await createPractice(deps, adminUserId, practiceName, 'MONTHLY');
    } catch (err: any) {
      expect(err.details).toEqual({ code: 'ALREADY_PRACTICE_ADMIN' });
    }
  });

  it('rejects if user is already on another practice', async () => {
    mockMembershipRepo.findActiveMembershipByPhysicianId.mockResolvedValue({
      membershipId: crypto.randomUUID(),
      practiceId: crypto.randomUUID(),
      physicianUserId: adminUserId,
      isActive: true,
    });

    await expect(
      createPractice(deps, adminUserId, practiceName, 'MONTHLY'),
    ).rejects.toThrow('User is already a member of a practice');

    try {
      await createPractice(deps, adminUserId, practiceName, 'MONTHLY');
    } catch (err: any) {
      expect(err.details).toEqual({ code: 'ALREADY_ON_PRACTICE' });
    }
  });

  // -------------------------------------------------------------------------
  // Billing mode determination
  // -------------------------------------------------------------------------

  it('sets billing_mode to INDIVIDUAL_EARLY_BIRD if admin has active early bird', async () => {
    (mockSubscriptionRepo.findActiveEarlyBirdByProviderId as any).mockResolvedValue({
      plan: 'EARLY_BIRD_MONTHLY',
      status: 'ACTIVE',
      earlyBirdLockedUntil: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000), // 6 months from now
    });

    await createPractice(deps, adminUserId, practiceName, 'MONTHLY');

    expect(createdMemberships).toHaveLength(1);
    expect(createdMemberships[0].billingMode).toBe('INDIVIDUAL_EARLY_BIRD');
  });

  it('sets billing_mode to PRACTICE_CONSOLIDATED if admin has no early bird', async () => {
    (mockSubscriptionRepo.findActiveEarlyBirdByProviderId as any).mockResolvedValue(null);

    await createPractice(deps, adminUserId, practiceName, 'MONTHLY');

    expect(createdMemberships).toHaveLength(1);
    expect(createdMemberships[0].billingMode).toBe('PRACTICE_CONSOLIDATED');
  });

  it('sets billing_mode to INDIVIDUAL_EARLY_BIRD for early bird annual plan', async () => {
    (mockSubscriptionRepo.findActiveEarlyBirdByProviderId as any).mockResolvedValue({
      plan: 'EARLY_BIRD_ANNUAL',
      status: 'ACTIVE',
      earlyBirdLockedUntil: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000), // 6 months from now
    });

    await createPractice(deps, adminUserId, practiceName, 'MONTHLY');

    expect(createdMemberships[0].billingMode).toBe('INDIVIDUAL_EARLY_BIRD');
  });

  it('sets billing_mode to PRACTICE_CONSOLIDATED for standard subscription', async () => {
    (mockSubscriptionRepo.findActiveEarlyBirdByProviderId as any).mockResolvedValue({
      plan: 'STANDARD_MONTHLY',
      status: 'ACTIVE',
    });

    await createPractice(deps, adminUserId, practiceName, 'MONTHLY');

    expect(createdMemberships[0].billingMode).toBe('PRACTICE_CONSOLIDATED');
  });

  // -------------------------------------------------------------------------
  // Period calculations
  // -------------------------------------------------------------------------

  it('sets correct current_period_end for MONTHLY billing', async () => {
    const before = new Date();
    const result = await createPractice(deps, adminUserId, practiceName, 'MONTHLY');

    const createCall = mockPracticeRepo.createPractice.mock.calls[0][0];
    const start = createCall.currentPeriodStart as Date;
    const end = createCall.currentPeriodEnd as Date;

    // Period end should be approximately 1 month from start
    const expectedEnd = new Date(start);
    expectedEnd.setMonth(expectedEnd.getMonth() + 1);
    expect(end.getTime()).toBe(expectedEnd.getTime());
  });

  it('sets correct current_period_end for ANNUAL billing', async () => {
    const result = await createPractice(deps, adminUserId, practiceName, 'ANNUAL');

    const createCall = mockPracticeRepo.createPractice.mock.calls[0][0];
    const start = createCall.currentPeriodStart as Date;
    const end = createCall.currentPeriodEnd as Date;

    // Period end should be approximately 1 year from start
    const expectedEnd = new Date(start);
    expectedEnd.setFullYear(expectedEnd.getFullYear() + 1);
    expect(end.getTime()).toBe(expectedEnd.getTime());

    expect(result.billingFrequency).toBe('ANNUAL');
  });

  // -------------------------------------------------------------------------
  // Audit logging
  // -------------------------------------------------------------------------

  it('audit logs the practice creation', async () => {
    await createPractice(deps, adminUserId, practiceName, 'MONTHLY');

    expect(auditLogs).toHaveLength(1);
    expect(auditLogs[0]).toEqual(
      expect.objectContaining({
        action: 'practice.created',
        resourceType: 'practice',
        actorType: 'physician',
        metadata: expect.objectContaining({
          adminUserId,
          practiceName,
        }),
      }),
    );
    expect(auditLogs[0].resourceId).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // Stripe failure rollback
  // -------------------------------------------------------------------------

  it('rolls back on Stripe customer creation failure', async () => {
    (mockStripe.customers.create as any).mockRejectedValue(
      new Error('Stripe API unavailable'),
    );

    await expect(
      createPractice(deps, adminUserId, practiceName, 'MONTHLY'),
    ).rejects.toThrow('Stripe API unavailable');

    // Practice was created (in a real transaction this would be rolled back)
    // but updatePractice should NOT have been called with Stripe ID
    expect(mockPracticeRepo.updatePractice).not.toHaveBeenCalled();
  });
});

// ===========================================================================
// Practice Service — invitePhysician
// ===========================================================================

describe('invitePhysician', () => {
  const adminUserId = crypto.randomUUID();
  const practiceId = crypto.randomUUID();
  const invitedEmail = 'dr.jones@example.com';
  let deps: PracticeServiceDeps;
  let mockPracticeRepo: any;
  let mockMembershipRepo: any;
  let mockInvitationRepo: any;
  let mockUserRepo: PracticeUserRepo;
  let mockSubscriptionRepo: PracticeSubscriptionRepo;
  let mockStripe: PracticeStripeClient;
  let mockNotifier: PracticeNotifier;
  let mockAuditLogger: PracticeAuditLogger;
  let auditLogs: any[];
  let createdInvitations: any[];
  let sentEmails: any[];

  beforeEach(() => {
    auditLogs = [];
    createdInvitations = [];
    sentEmails = [];

    mockPracticeRepo = {
      findPracticeById: vi.fn().mockResolvedValue({
        practiceId,
        name: 'Alpine Family Clinic',
        adminUserId,
        status: 'ACTIVE',
        billingFrequency: 'MONTHLY',
        stripeCustomerId: 'cus_123',
        stripeSubscriptionId: null,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        createdAt: new Date(),
        updatedAt: new Date(),
      }),
      findPracticeByAdminUserId: vi.fn().mockResolvedValue(null),
      createPractice: vi.fn(),
      updatePractice: vi.fn(),
    };

    mockMembershipRepo = {
      findActiveMembershipByPhysicianId: vi.fn().mockResolvedValue(null),
      findMembershipByPracticeAndPhysician: vi.fn().mockResolvedValue(null),
      createMembership: vi.fn(),
    };

    mockInvitationRepo = {
      findPendingInvitationByEmail: vi.fn().mockResolvedValue(null),
      createInvitation: vi.fn().mockImplementation(async (data: any) => {
        const invitation = {
          invitationId: crypto.randomUUID(),
          practiceId: data.practiceId,
          invitedEmail: data.invitedEmail,
          invitedByUserId: data.invitedByUserId,
          status: data.status,
          tokenHash: data.tokenHash,
          expiresAt: data.expiresAt,
          createdAt: new Date(),
        };
        createdInvitations.push(invitation);
        return invitation;
      }),
    };

    mockUserRepo = {
      findUserById: vi.fn().mockResolvedValue({
        userId: adminUserId,
        email: 'dr.smith@example.com',
        fullName: 'Dr. Smith',
        role: 'PRACTICE_ADMIN',
      }),
      findUserByEmail: vi.fn().mockResolvedValue(undefined),
      updateUserRole: vi.fn(),
    };

    mockSubscriptionRepo = {
      findActiveEarlyBirdByProviderId: vi.fn().mockResolvedValue(null),
    };

    mockStripe = {
      customers: {
        create: vi.fn().mockResolvedValue({ id: 'cus_test' }),
      },
    };

    mockNotifier = {
      sendInvitationEmail: vi.fn().mockImplementation(async (params: any) => {
        sentEmails.push(params);
      }),
    };

    mockAuditLogger = {
      log: vi.fn().mockImplementation(async (entry: any) => {
        auditLogs.push(entry);
      }),
    };

    deps = {
      practiceRepo: mockPracticeRepo,
      membershipRepo: mockMembershipRepo,
      invitationRepo: mockInvitationRepo,
      userRepo: mockUserRepo,
      subscriptionRepo: mockSubscriptionRepo,
      stripe: mockStripe,
      notifier: mockNotifier,
      auditLogger: mockAuditLogger,
    };
  });

  // -------------------------------------------------------------------------
  // Happy path
  // -------------------------------------------------------------------------

  it('creates an invitation with correct practice ID and email', async () => {
    const result = await invitePhysician(deps, practiceId, invitedEmail, adminUserId);

    expect(result).toBeDefined();
    expect(result.practiceId).toBe(practiceId);
    expect(result.invitedEmail).toBe(invitedEmail.toLowerCase());
    expect(result.invitedByUserId).toBe(adminUserId);
    expect(result.status).toBe('PENDING');
  });

  it('generates a hashed token and stores only the hash', async () => {
    const result = await invitePhysician(deps, practiceId, invitedEmail, adminUserId);

    expect(result.tokenHash).toBeDefined();
    expect(result.tokenHash).toHaveLength(64); // SHA-256 hex = 64 chars
    // Verify the createInvitation was called with a tokenHash, not the raw token
    const createCall = mockInvitationRepo.createInvitation.mock.calls[0][0];
    expect(createCall.tokenHash).toHaveLength(64);
  });

  it('sets expiry to 7 days from now', async () => {
    const before = new Date();
    const result = await invitePhysician(deps, practiceId, invitedEmail, adminUserId);
    const after = new Date();

    const sevenDaysFromBefore = new Date(before);
    sevenDaysFromBefore.setDate(sevenDaysFromBefore.getDate() + 7);

    const sevenDaysFromAfter = new Date(after);
    sevenDaysFromAfter.setDate(sevenDaysFromAfter.getDate() + 7);

    expect(result.expiresAt.getTime()).toBeGreaterThanOrEqual(sevenDaysFromBefore.getTime() - 1000);
    expect(result.expiresAt.getTime()).toBeLessThanOrEqual(sevenDaysFromAfter.getTime() + 1000);
  });

  it('emits a notification email to the invited physician', async () => {
    await invitePhysician(deps, practiceId, invitedEmail, adminUserId);

    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0].toEmail).toBe(invitedEmail.toLowerCase());
    expect(sentEmails[0].practiceName).toBe('Alpine Family Clinic');
    expect(sentEmails[0].inviterName).toBe('Dr. Smith');
    expect(sentEmails[0].acceptUrl).toContain('token=');
    // The URL should contain a 64-char hex token (the raw token, not the hash)
    const urlToken = sentEmails[0].acceptUrl.split('token=')[1];
    expect(urlToken).toHaveLength(64);
  });

  it('normalizes email to lowercase before checking', async () => {
    const mixedCaseEmail = '  Dr.Jones@Example.COM  ';
    await invitePhysician(deps, practiceId, mixedCaseEmail, adminUserId);

    expect(createdInvitations).toHaveLength(1);
    expect(createdInvitations[0].invitedEmail).toBe('dr.jones@example.com');
    // Also verify the findPendingInvitationByEmail was called with lowercase
    expect(mockInvitationRepo.findPendingInvitationByEmail).toHaveBeenCalledWith(
      'dr.jones@example.com',
      practiceId,
    );
  });

  it('audit logs the invitation', async () => {
    await invitePhysician(deps, practiceId, invitedEmail, adminUserId);

    expect(auditLogs).toHaveLength(1);
    expect(auditLogs[0]).toEqual(
      expect.objectContaining({
        action: 'practice.invitation_sent',
        resourceType: 'practice_invitation',
        actorType: 'physician',
        metadata: expect.objectContaining({
          practiceId,
          invitedEmail: invitedEmail.toLowerCase(),
          invitedByUserId: adminUserId,
        }),
      }),
    );
    expect(auditLogs[0].resourceId).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // Validation errors
  // -------------------------------------------------------------------------

  it('rejects if inviter is not PRACTICE_ADMIN for this practice', async () => {
    const otherUserId = crypto.randomUUID();

    await expect(
      invitePhysician(deps, practiceId, invitedEmail, otherUserId),
    ).rejects.toThrow('Not a practice admin');
  });

  it('rejects if practice is not ACTIVE', async () => {
    mockPracticeRepo.findPracticeById.mockResolvedValue({
      practiceId,
      name: 'Suspended Clinic',
      adminUserId,
      status: 'SUSPENDED',
      billingFrequency: 'MONTHLY',
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await expect(
      invitePhysician(deps, practiceId, invitedEmail, adminUserId),
    ).rejects.toThrow('Practice is not active');

    try {
      await invitePhysician(deps, practiceId, invitedEmail, adminUserId);
    } catch (err: any) {
      expect(err.details).toEqual({ code: 'PRACTICE_NOT_ACTIVE' });
    }
  });

  it('rejects if email is already a member of this practice', async () => {
    const existingUserId = crypto.randomUUID();
    (mockUserRepo.findUserByEmail as any).mockResolvedValue({
      userId: existingUserId,
      email: invitedEmail,
      fullName: 'Dr. Jones',
      role: 'PHYSICIAN',
    });
    mockMembershipRepo.findMembershipByPracticeAndPhysician.mockResolvedValue({
      membershipId: crypto.randomUUID(),
      practiceId,
      physicianUserId: existingUserId,
      isActive: true,
    });

    await expect(
      invitePhysician(deps, practiceId, invitedEmail, adminUserId),
    ).rejects.toThrow('User is already a member of this practice');

    try {
      await invitePhysician(deps, practiceId, invitedEmail, adminUserId);
    } catch (err: any) {
      expect(err.details).toEqual({ code: 'ALREADY_ON_PRACTICE' });
    }
  });

  it('rejects if email is already on another active practice', async () => {
    const existingUserId = crypto.randomUUID();
    const otherPracticeId = crypto.randomUUID();
    (mockUserRepo.findUserByEmail as any).mockResolvedValue({
      userId: existingUserId,
      email: invitedEmail,
      fullName: 'Dr. Jones',
      role: 'PHYSICIAN',
    });
    mockMembershipRepo.findMembershipByPracticeAndPhysician.mockResolvedValue(null);
    mockMembershipRepo.findActiveMembershipByPhysicianId.mockResolvedValue({
      membershipId: crypto.randomUUID(),
      practiceId: otherPracticeId,
      physicianUserId: existingUserId,
      isActive: true,
    });

    await expect(
      invitePhysician(deps, practiceId, invitedEmail, adminUserId),
    ).rejects.toThrow('User is already a member of another practice');

    try {
      await invitePhysician(deps, practiceId, invitedEmail, adminUserId);
    } catch (err: any) {
      expect(err.details).toEqual({ code: 'ON_ANOTHER_PRACTICE' });
    }
  });

  it('rejects if a pending invitation already exists for this email+practice', async () => {
    mockInvitationRepo.findPendingInvitationByEmail.mockResolvedValue({
      invitationId: crypto.randomUUID(),
      practiceId,
      invitedEmail,
      status: 'PENDING',
    });

    await expect(
      invitePhysician(deps, practiceId, invitedEmail, adminUserId),
    ).rejects.toThrow('An invitation is already pending for this email');

    try {
      await invitePhysician(deps, practiceId, invitedEmail, adminUserId);
    } catch (err: any) {
      expect(err.details).toEqual({ code: 'INVITATION_ALREADY_PENDING' });
    }
  });
});

// ===========================================================================
// Practice Service — acceptInvitation
// ===========================================================================

describe('acceptInvitation', () => {
  const adminUserId = crypto.randomUUID();
  const acceptingUserId = crypto.randomUUID();
  const practiceId = crypto.randomUUID();
  const invitationId = crypto.randomUUID();
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const acceptingEmail = 'dr.jones@example.com';

  let deps: PracticeServiceDeps;
  let mockPracticeRepo: any;
  let mockMembershipRepo: any;
  let mockInvitationRepo: any;
  let mockUserRepo: PracticeUserRepo;
  let mockSubscriptionRepo: PracticeSubscriptionRepo;
  let mockStripe: PracticeStripeClient;
  let mockAuditLogger: PracticeAuditLogger;
  let auditLogs: any[];
  let createdMemberships: any[];
  let invitationStatusUpdates: Array<{ id: string; status: string }>;
  let stripeCancellations: string[];
  let stripeSubscriptionUpdates: any[];

  function makeInvitation(overrides: Partial<Record<string, any>> = {}) {
    return {
      invitationId: overrides.invitationId ?? invitationId,
      practiceId: overrides.practiceId ?? practiceId,
      invitedEmail: overrides.invitedEmail ?? acceptingEmail,
      invitedByUserId: overrides.invitedByUserId ?? adminUserId,
      status: overrides.status ?? 'PENDING',
      tokenHash: overrides.tokenHash ?? tokenHash,
      expiresAt: overrides.expiresAt ?? new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      createdAt: overrides.createdAt ?? new Date(),
    };
  }

  beforeEach(() => {
    auditLogs = [];
    createdMemberships = [];
    invitationStatusUpdates = [];
    stripeCancellations = [];
    stripeSubscriptionUpdates = [];

    mockPracticeRepo = {
      findPracticeById: vi.fn().mockResolvedValue({
        practiceId,
        name: 'Alpine Family Clinic',
        adminUserId,
        status: 'ACTIVE',
        billingFrequency: 'MONTHLY',
        stripeCustomerId: 'cus_practice_123',
        stripeSubscriptionId: 'sub_practice_456',
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        createdAt: new Date(),
        updatedAt: new Date(),
      }),
      findPracticeByAdminUserId: vi.fn().mockResolvedValue(null),
      createPractice: vi.fn(),
      updatePractice: vi.fn(),
      getConsolidatedSeatCount: vi.fn().mockResolvedValue(2),
    };

    mockMembershipRepo = {
      findActiveMembershipByPhysicianId: vi.fn().mockResolvedValue(null),
      findMembershipByPracticeAndPhysician: vi.fn().mockResolvedValue(null),
      createMembership: vi.fn().mockImplementation(async (data: any) => {
        const membership = {
          membershipId: crypto.randomUUID(),
          practiceId: data.practiceId,
          physicianUserId: data.physicianUserId,
          billingMode: data.billingMode ?? 'PRACTICE_CONSOLIDATED',
          joinedAt: data.joinedAt ?? new Date(),
          removedAt: null,
          removalEffectiveAt: null,
          isActive: true,
          createdAt: new Date(),
        };
        createdMemberships.push(membership);
        return membership;
      }),
    };

    mockInvitationRepo = {
      findInvitationByTokenHash: vi.fn().mockResolvedValue(makeInvitation()),
      findPendingInvitationByEmail: vi.fn().mockResolvedValue(null),
      createInvitation: vi.fn(),
      updateInvitationStatus: vi.fn().mockImplementation(async (id: string, status: string) => {
        invitationStatusUpdates.push({ id, status });
      }),
    };

    mockUserRepo = {
      findUserById: vi.fn().mockResolvedValue({
        userId: acceptingUserId,
        email: acceptingEmail,
        fullName: 'Dr. Jones',
        role: 'PHYSICIAN',
      }),
      findUserByEmail: vi.fn().mockResolvedValue(undefined),
      updateUserRole: vi.fn(),
    };

    mockSubscriptionRepo = {
      findActiveEarlyBirdByProviderId: vi.fn().mockResolvedValue(null),
      findActiveSubscriptionByProviderId: vi.fn().mockResolvedValue(null),
    };

    mockStripe = {
      customers: {
        create: vi.fn().mockResolvedValue({ id: 'cus_test' }),
      },
      subscriptions: {
        cancel: vi.fn().mockImplementation(async (subId: string) => {
          stripeCancellations.push(subId);
          return { id: subId, status: 'canceled' };
        }),
        update: vi.fn().mockImplementation(async (subId: string, params: any) => {
          stripeSubscriptionUpdates.push({ subId, ...params });
          return { id: subId, quantity: params.quantity };
        }),
      },
    };

    mockAuditLogger = {
      log: vi.fn().mockImplementation(async (entry: any) => {
        auditLogs.push(entry);
      }),
    };

    deps = {
      practiceRepo: mockPracticeRepo,
      membershipRepo: mockMembershipRepo,
      invitationRepo: mockInvitationRepo,
      userRepo: mockUserRepo,
      subscriptionRepo: mockSubscriptionRepo,
      stripe: mockStripe,
      auditLogger: mockAuditLogger,
    };
  });

  // -------------------------------------------------------------------------
  // Happy path
  // -------------------------------------------------------------------------

  it('creates a membership when token is valid and invitation is pending', async () => {
    const result = await acceptInvitation(deps, rawToken, acceptingUserId);

    expect(result).toBeDefined();
    expect(result.practiceId).toBe(practiceId);
    expect(result.physicianUserId).toBe(acceptingUserId);
    expect(result.isActive).toBe(true);
    expect(result.joinedAt).toBeInstanceOf(Date);
  });

  it('sets billing_mode to INDIVIDUAL_EARLY_BIRD when physician has active early bird', async () => {
    (mockSubscriptionRepo.findActiveEarlyBirdByProviderId as any).mockResolvedValue({
      plan: 'EARLY_BIRD_MONTHLY',
      status: 'ACTIVE',
      earlyBirdLockedUntil: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000),
    });

    const result = await acceptInvitation(deps, rawToken, acceptingUserId);

    expect(result.billingMode).toBe('INDIVIDUAL_EARLY_BIRD');
  });

  it('sets billing_mode to PRACTICE_CONSOLIDATED when physician has no early bird', async () => {
    (mockSubscriptionRepo.findActiveEarlyBirdByProviderId as any).mockResolvedValue(null);

    const result = await acceptInvitation(deps, rawToken, acceptingUserId);

    expect(result.billingMode).toBe('PRACTICE_CONSOLIDATED');
  });

  it('does NOT increment Stripe quantity for INDIVIDUAL_EARLY_BIRD members', async () => {
    (mockSubscriptionRepo.findActiveEarlyBirdByProviderId as any).mockResolvedValue({
      plan: 'EARLY_BIRD_ANNUAL',
      status: 'ACTIVE',
      earlyBirdLockedUntil: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000),
    });

    await acceptInvitation(deps, rawToken, acceptingUserId);

    expect(stripeSubscriptionUpdates).toHaveLength(0);
  });

  it('increments Stripe quantity for PRACTICE_CONSOLIDATED members', async () => {
    (mockSubscriptionRepo.findActiveEarlyBirdByProviderId as any).mockResolvedValue(null);
    mockPracticeRepo.getConsolidatedSeatCount.mockResolvedValue(3);

    await acceptInvitation(deps, rawToken, acceptingUserId);

    expect(stripeSubscriptionUpdates).toHaveLength(1);
    expect(stripeSubscriptionUpdates[0].subId).toBe('sub_practice_456');
    expect(stripeSubscriptionUpdates[0].quantity).toBe(3);
  });

  it('cancels individual subscription when transitioning to PRACTICE_CONSOLIDATED', async () => {
    (mockSubscriptionRepo.findActiveEarlyBirdByProviderId as any).mockResolvedValue(null);
    (mockSubscriptionRepo as any).findActiveSubscriptionByProviderId.mockResolvedValue({
      subscriptionId: crypto.randomUUID(),
      stripeSubscriptionId: 'sub_individual_789',
      plan: 'STANDARD_MONTHLY',
      status: 'ACTIVE',
    });

    await acceptInvitation(deps, rawToken, acceptingUserId);

    expect(stripeCancellations).toHaveLength(1);
    expect(stripeCancellations[0]).toBe('sub_individual_789');
  });

  it('keeps individual early bird subscription intact for INDIVIDUAL_EARLY_BIRD', async () => {
    (mockSubscriptionRepo.findActiveEarlyBirdByProviderId as any).mockResolvedValue({
      plan: 'EARLY_BIRD_MONTHLY',
      status: 'ACTIVE',
      earlyBirdLockedUntil: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000),
    });

    await acceptInvitation(deps, rawToken, acceptingUserId);

    // Should NOT cancel any individual subscription
    expect(stripeCancellations).toHaveLength(0);
    expect(stripeSubscriptionUpdates).toHaveLength(0);
  });

  it('treats expired early bird (locked_until in past) as PRACTICE_CONSOLIDATED', async () => {
    (mockSubscriptionRepo.findActiveEarlyBirdByProviderId as any).mockResolvedValue({
      plan: 'EARLY_BIRD_MONTHLY',
      status: 'ACTIVE',
      earlyBirdLockedUntil: new Date(Date.now() - 24 * 60 * 60 * 1000), // expired yesterday
    });

    const result = await acceptInvitation(deps, rawToken, acceptingUserId);

    expect(result.billingMode).toBe('PRACTICE_CONSOLIDATED');
  });

  it('treats early bird with null earlyBirdLockedUntil as PRACTICE_CONSOLIDATED', async () => {
    (mockSubscriptionRepo.findActiveEarlyBirdByProviderId as any).mockResolvedValue({
      plan: 'EARLY_BIRD_MONTHLY',
      status: 'ACTIVE',
      earlyBirdLockedUntil: null,
    });

    const result = await acceptInvitation(deps, rawToken, acceptingUserId);

    expect(result.billingMode).toBe('PRACTICE_CONSOLIDATED');
  });

  it('updates invitation status to ACCEPTED', async () => {
    await acceptInvitation(deps, rawToken, acceptingUserId);

    expect(invitationStatusUpdates).toHaveLength(1);
    expect(invitationStatusUpdates[0].id).toBe(invitationId);
    expect(invitationStatusUpdates[0].status).toBe('ACCEPTED');
  });

  // -------------------------------------------------------------------------
  // Validation errors
  // -------------------------------------------------------------------------

  it('rejects invalid token', async () => {
    mockInvitationRepo.findInvitationByTokenHash.mockResolvedValue(null);

    await expect(
      acceptInvitation(deps, 'invalid-token-value', acceptingUserId),
    ).rejects.toThrow('Invitation not found');
  });

  it('rejects already accepted invitation', async () => {
    mockInvitationRepo.findInvitationByTokenHash.mockResolvedValue(
      makeInvitation({ status: 'ACCEPTED' }),
    );

    await expect(
      acceptInvitation(deps, rawToken, acceptingUserId),
    ).rejects.toThrow('Invitation is not pending');

    try {
      await acceptInvitation(deps, rawToken, acceptingUserId);
    } catch (err: any) {
      expect(err.details).toEqual({ code: 'INVITATION_NOT_PENDING' });
    }
  });

  it('rejects expired invitation', async () => {
    const expiredInvitation = makeInvitation({
      expiresAt: new Date(Date.now() - 1000), // 1 second in the past
    });
    mockInvitationRepo.findInvitationByTokenHash.mockResolvedValue(expiredInvitation);

    await expect(
      acceptInvitation(deps, rawToken, acceptingUserId),
    ).rejects.toThrow('Invitation has expired');

    // Verify it updated the invitation status to EXPIRED
    expect(invitationStatusUpdates).toContainEqual({
      id: invitationId,
      status: 'EXPIRED',
    });
  });

  it('rejects if accepting user email does not match invitation email', async () => {
    (mockUserRepo.findUserById as any).mockResolvedValue({
      userId: acceptingUserId,
      email: 'different.email@example.com',
      fullName: 'Dr. Different',
      role: 'PHYSICIAN',
    });

    await expect(
      acceptInvitation(deps, rawToken, acceptingUserId),
    ).rejects.toThrow('Email does not match invitation');
  });

  it('rejects if physician is already on another practice', async () => {
    mockMembershipRepo.findActiveMembershipByPhysicianId.mockResolvedValue({
      membershipId: crypto.randomUUID(),
      practiceId: crypto.randomUUID(),
      physicianUserId: acceptingUserId,
      isActive: true,
    });

    await expect(
      acceptInvitation(deps, rawToken, acceptingUserId),
    ).rejects.toThrow('Physician is already a member of a practice');

    try {
      await acceptInvitation(deps, rawToken, acceptingUserId);
    } catch (err: any) {
      expect(err.details).toEqual({ code: 'ALREADY_ON_PRACTICE' });
    }
  });

  // -------------------------------------------------------------------------
  // Audit logging
  // -------------------------------------------------------------------------

  it('audit logs the acceptance with billing mode', async () => {
    await acceptInvitation(deps, rawToken, acceptingUserId);

    expect(auditLogs).toHaveLength(1);
    expect(auditLogs[0]).toEqual(
      expect.objectContaining({
        action: 'practice.invitation_accepted',
        resourceType: 'practice_membership',
        actorType: 'physician',
        metadata: expect.objectContaining({
          practiceId,
          physicianUserId: acceptingUserId,
          billingMode: 'PRACTICE_CONSOLIDATED',
          invitationId,
        }),
      }),
    );
    expect(auditLogs[0].resourceId).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // Stripe proration
  // -------------------------------------------------------------------------

  it('prorates Stripe subscription update', async () => {
    (mockSubscriptionRepo.findActiveEarlyBirdByProviderId as any).mockResolvedValue(null);

    await acceptInvitation(deps, rawToken, acceptingUserId);

    expect(stripeSubscriptionUpdates).toHaveLength(1);
    expect(stripeSubscriptionUpdates[0].proration_behavior).toBe('create_prorations');
  });
});

// ===========================================================================
// Practice Service — removePhysician
// ===========================================================================

describe('removePhysician', () => {
  const adminUserId = crypto.randomUUID();
  const physicianUserId = crypto.randomUUID();
  const practiceId = crypto.randomUUID();
  const membershipId = crypto.randomUUID();

  let deps: PracticeServiceDeps;
  let mockPracticeRepo: any;
  let mockMembershipRepo: any;
  let mockUserRepo: PracticeUserRepo;
  let mockSubscriptionRepo: PracticeSubscriptionRepo;
  let mockStripe: PracticeStripeClient;
  let mockNotifier: PracticeNotifier;
  let mockAuditLogger: PracticeAuditLogger;
  let auditLogs: any[];
  let removalSchedules: any[];
  let removalNotifications: any[];
  let headcountWarnings: any[];

  beforeEach(() => {
    auditLogs = [];
    removalSchedules = [];
    removalNotifications = [];
    headcountWarnings = [];

    mockPracticeRepo = {
      findPracticeById: vi.fn().mockResolvedValue({
        practiceId,
        name: 'Alpine Family Clinic',
        adminUserId,
        status: 'ACTIVE',
        billingFrequency: 'MONTHLY',
        stripeCustomerId: 'cus_123',
        stripeSubscriptionId: 'sub_456',
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        createdAt: new Date(),
        updatedAt: new Date(),
      }),
      findPracticeByAdminUserId: vi.fn(),
      createPractice: vi.fn(),
      updatePractice: vi.fn(),
      getActiveHeadcount: vi.fn().mockResolvedValue(6),
      getConsolidatedSeatCount: vi.fn(),
    };

    mockMembershipRepo = {
      findActiveMembershipByPhysicianId: vi.fn(),
      findMembershipByPracticeAndPhysician: vi.fn().mockResolvedValue({
        membershipId,
        practiceId,
        physicianUserId,
        billingMode: 'PRACTICE_CONSOLIDATED',
        joinedAt: new Date(),
        removedAt: null,
        removalEffectiveAt: null,
        isActive: true,
        createdAt: new Date(),
      }),
      createMembership: vi.fn(),
      setRemovalScheduled: vi.fn().mockImplementation(
        async (mId: string, removedAt: Date, effectiveAt: Date) => {
          removalSchedules.push({ membershipId: mId, removedAt, removalEffectiveAt: effectiveAt });
        },
      ),
      deactivateMembership: vi.fn(),
    };

    mockUserRepo = {
      findUserById: vi.fn().mockImplementation(async (userId: string) => {
        if (userId === adminUserId) {
          return {
            userId: adminUserId,
            email: 'admin@example.com',
            fullName: 'Dr. Admin',
            role: 'PRACTICE_ADMIN',
          };
        }
        if (userId === physicianUserId) {
          return {
            userId: physicianUserId,
            email: 'physician@example.com',
            fullName: 'Dr. Physician',
            role: 'PHYSICIAN',
          };
        }
        return undefined;
      }),
      findUserByEmail: vi.fn(),
      updateUserRole: vi.fn(),
    };

    mockSubscriptionRepo = {
      findActiveEarlyBirdByProviderId: vi.fn().mockResolvedValue(null),
    };

    mockStripe = {
      customers: {
        create: vi.fn().mockResolvedValue({ id: 'cus_test' }),
      },
    };

    mockNotifier = {
      sendInvitationEmail: vi.fn(),
      sendRemovalNotification: vi.fn().mockImplementation(async (params: any) => {
        removalNotifications.push(params);
      }),
      sendHeadcountWarning: vi.fn().mockImplementation(async (params: any) => {
        headcountWarnings.push(params);
      }),
    };

    mockAuditLogger = {
      log: vi.fn().mockImplementation(async (entry: any) => {
        auditLogs.push(entry);
      }),
    };

    deps = {
      practiceRepo: mockPracticeRepo,
      membershipRepo: mockMembershipRepo,
      invitationRepo: {} as any,
      userRepo: mockUserRepo,
      subscriptionRepo: mockSubscriptionRepo,
      stripe: mockStripe,
      notifier: mockNotifier,
      auditLogger: mockAuditLogger,
    };
  });

  // -------------------------------------------------------------------------
  // Happy path
  // -------------------------------------------------------------------------

  it('schedules removal for end of current calendar month', async () => {
    await removePhysician(deps, practiceId, physicianUserId, adminUserId);

    expect(removalSchedules).toHaveLength(1);
    const schedule = removalSchedules[0];

    const now = new Date();
    const expectedYear = now.getUTCFullYear();
    const expectedMonth = now.getUTCMonth();
    const lastDay = new Date(Date.UTC(expectedYear, expectedMonth + 1, 0));

    expect(schedule.removalEffectiveAt.getUTCFullYear()).toBe(expectedYear);
    expect(schedule.removalEffectiveAt.getUTCMonth()).toBe(expectedMonth);
    expect(schedule.removalEffectiveAt.getUTCDate()).toBe(lastDay.getUTCDate());
    expect(schedule.removalEffectiveAt.getUTCHours()).toBe(23);
    expect(schedule.removalEffectiveAt.getUTCMinutes()).toBe(59);
    expect(schedule.removalEffectiveAt.getUTCSeconds()).toBe(59);
    expect(schedule.removalEffectiveAt.getUTCMilliseconds()).toBe(999);
  });

  it('sets removed_at to now', async () => {
    const before = new Date();
    await removePhysician(deps, practiceId, physicianUserId, adminUserId);
    const after = new Date();

    expect(removalSchedules).toHaveLength(1);
    const removedAt = removalSchedules[0].removedAt;
    expect(removedAt.getTime()).toBeGreaterThanOrEqual(before.getTime());
    expect(removedAt.getTime()).toBeLessThanOrEqual(after.getTime());
  });

  it('does NOT set is_active to false immediately', async () => {
    await removePhysician(deps, practiceId, physicianUserId, adminUserId);

    // setRemovalScheduled was called, NOT deactivateMembership
    expect(mockMembershipRepo.setRemovalScheduled).toHaveBeenCalledTimes(1);
    expect(mockMembershipRepo.deactivateMembership).not.toHaveBeenCalled();
  });

  it('physician retains access until removal_effective_at', async () => {
    await removePhysician(deps, practiceId, physicianUserId, adminUserId);

    // The membership is still active (setRemovalScheduled doesn't change isActive)
    // Verify deactivateMembership was NOT called
    expect(mockMembershipRepo.deactivateMembership).not.toHaveBeenCalled();

    // And the effective date is in the future (end of month)
    const schedule = removalSchedules[0];
    expect(schedule.removalEffectiveAt.getTime()).toBeGreaterThan(Date.now());
  });

  // -------------------------------------------------------------------------
  // Validation errors
  // -------------------------------------------------------------------------

  it('rejects if remover is not PRACTICE_ADMIN', async () => {
    const nonAdminUserId = crypto.randomUUID();

    await expect(
      removePhysician(deps, practiceId, physicianUserId, nonAdminUserId),
    ).rejects.toThrow('Not a practice admin');
  });

  it('rejects if trying to remove the admin', async () => {
    await expect(
      removePhysician(deps, practiceId, adminUserId, adminUserId),
    ).rejects.toThrow('Cannot remove the practice admin');

    try {
      await removePhysician(deps, practiceId, adminUserId, adminUserId);
    } catch (err: any) {
      expect(err.details).toEqual({ code: 'CANNOT_REMOVE_ADMIN' });
    }
  });

  it('rejects if membership not found', async () => {
    mockMembershipRepo.findMembershipByPracticeAndPhysician.mockResolvedValue(null);

    await expect(
      removePhysician(deps, practiceId, physicianUserId, adminUserId),
    ).rejects.toThrow('Membership not found');
  });

  it('rejects if removal already scheduled', async () => {
    mockMembershipRepo.findMembershipByPracticeAndPhysician.mockResolvedValue({
      membershipId,
      practiceId,
      physicianUserId,
      billingMode: 'PRACTICE_CONSOLIDATED',
      joinedAt: new Date(),
      removedAt: new Date(),
      removalEffectiveAt: new Date(Date.now() + 10 * 24 * 60 * 60 * 1000),
      isActive: true,
      createdAt: new Date(),
    });

    await expect(
      removePhysician(deps, practiceId, physicianUserId, adminUserId),
    ).rejects.toThrow('Removal is already scheduled for this physician');

    try {
      await removePhysician(deps, practiceId, physicianUserId, adminUserId);
    } catch (err: any) {
      expect(err.details).toEqual({ code: 'REMOVAL_ALREADY_SCHEDULED' });
    }
  });

  // -------------------------------------------------------------------------
  // Headcount warning
  // -------------------------------------------------------------------------

  it('emits headcount warning if practice drops below 5', async () => {
    // Current headcount is 5, removing 1 → projected 4 < 5
    mockPracticeRepo.getActiveHeadcount.mockResolvedValue(5);

    await removePhysician(deps, practiceId, physicianUserId, adminUserId);

    expect(headcountWarnings).toHaveLength(1);
    expect(headcountWarnings[0].toEmail).toBe('admin@example.com');
    expect(headcountWarnings[0].practiceName).toBe('Alpine Family Clinic');
    expect(headcountWarnings[0].projectedHeadcount).toBe(4);
  });

  it('does not emit headcount warning if practice remains at 5 or above', async () => {
    // Current headcount is 6, removing 1 → projected 5 >= 5
    mockPracticeRepo.getActiveHeadcount.mockResolvedValue(6);

    await removePhysician(deps, practiceId, physicianUserId, adminUserId);

    expect(headcountWarnings).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Notifications
  // -------------------------------------------------------------------------

  it('emits notification to removed physician', async () => {
    await removePhysician(deps, practiceId, physicianUserId, adminUserId);

    expect(removalNotifications).toHaveLength(1);
    expect(removalNotifications[0].toEmail).toBe('physician@example.com');
    expect(removalNotifications[0].practiceName).toBe('Alpine Family Clinic');
    expect(removalNotifications[0].effectiveDate).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // Audit logging
  // -------------------------------------------------------------------------

  it('audit logs the removal with effective date', async () => {
    await removePhysician(deps, practiceId, physicianUserId, adminUserId);

    const removalLog = auditLogs.find(
      (l: any) => l.action === 'practice.physician_removed',
    );
    expect(removalLog).toBeDefined();
    expect(removalLog).toEqual(
      expect.objectContaining({
        action: 'practice.physician_removed',
        resourceType: 'practice_membership',
        resourceId: membershipId,
        actorType: 'physician',
        metadata: expect.objectContaining({
          practiceId,
          physicianUserId,
          removedByUserId: adminUserId,
          removalEffectiveAt: expect.any(String),
        }),
      }),
    );
  });

  // -------------------------------------------------------------------------
  // End-of-month calculations
  // -------------------------------------------------------------------------

  it('calculates correct end-of-month for February', async () => {
    // Mock Date to Feb 16, 2026
    const realDate = Date;
    const mockDate = new Date(Date.UTC(2026, 1, 16, 12, 0, 0));
    vi.spyOn(globalThis, 'Date').mockImplementation(function (this: any, ...args: any[]) {
      if (args.length === 0) return mockDate;
      // @ts-expect-error -- calling Date constructor with spread args
      return new realDate(...args);
    } as any);
    // Preserve static methods
    (globalThis.Date as any).UTC = realDate.UTC;
    (globalThis.Date as any).now = () => mockDate.getTime();

    await removePhysician(deps, practiceId, physicianUserId, adminUserId);

    const schedule = removalSchedules[0];
    expect(schedule.removalEffectiveAt.getUTCMonth()).toBe(1); // Feb
    expect(schedule.removalEffectiveAt.getUTCDate()).toBe(28); // 2026 is not a leap year
    expect(schedule.removalEffectiveAt.getUTCHours()).toBe(23);
    expect(schedule.removalEffectiveAt.getUTCMinutes()).toBe(59);
    expect(schedule.removalEffectiveAt.getUTCSeconds()).toBe(59);

    vi.restoreAllMocks();
  });

  it('calculates correct end-of-month for months with 30 days', async () => {
    const realDate = Date;
    const mockDate = new Date(Date.UTC(2026, 3, 10, 12, 0, 0)); // April 10
    vi.spyOn(globalThis, 'Date').mockImplementation(function (this: any, ...args: any[]) {
      if (args.length === 0) return mockDate;
      // @ts-expect-error -- calling Date constructor with spread args
      return new realDate(...args);
    } as any);
    (globalThis.Date as any).UTC = realDate.UTC;
    (globalThis.Date as any).now = () => mockDate.getTime();

    await removePhysician(deps, practiceId, physicianUserId, adminUserId);

    const schedule = removalSchedules[0];
    expect(schedule.removalEffectiveAt.getUTCMonth()).toBe(3); // April
    expect(schedule.removalEffectiveAt.getUTCDate()).toBe(30);

    vi.restoreAllMocks();
  });

  it('calculates correct end-of-month for months with 31 days', async () => {
    const realDate = Date;
    const mockDate = new Date(Date.UTC(2026, 0, 5, 12, 0, 0)); // January 5
    vi.spyOn(globalThis, 'Date').mockImplementation(function (this: any, ...args: any[]) {
      if (args.length === 0) return mockDate;
      // @ts-expect-error -- calling Date constructor with spread args
      return new realDate(...args);
    } as any);
    (globalThis.Date as any).UTC = realDate.UTC;
    (globalThis.Date as any).now = () => mockDate.getTime();

    await removePhysician(deps, practiceId, physicianUserId, adminUserId);

    const schedule = removalSchedules[0];
    expect(schedule.removalEffectiveAt.getUTCMonth()).toBe(0); // January
    expect(schedule.removalEffectiveAt.getUTCDate()).toBe(31);

    vi.restoreAllMocks();
  });
});

// ===========================================================================
// Practice Service — handleEndOfMonthRemovals
// ===========================================================================

describe('handleEndOfMonthRemovals', () => {
  const adminUserId = crypto.randomUUID();
  const practiceId = crypto.randomUUID();

  let deps: PracticeServiceDeps;
  let mockPracticeRepo: any;
  let mockMembershipRepo: any;
  let mockUserRepo: PracticeUserRepo;
  let mockSubscriptionRepo: PracticeSubscriptionRepo;
  let mockStripe: PracticeStripeClient;
  let mockNotifier: PracticeNotifier;
  let mockAuditLogger: PracticeAuditLogger;
  let auditLogs: any[];
  let deactivatedMemberships: string[];
  let deactivatedAllPractices: string[];
  let stripeSubscriptionUpdates: any[];
  let stripeCancellations: string[];
  let stripeCustomersCreated: any[];
  let stripeSubscriptionsCreated: any[];
  let subscriptionsCreated: any[];
  let practiceStatusUpdates: any[];
  let dissolutionNotifications: any[];

  function makePendingRemoval(overrides: Partial<Record<string, any>> = {}) {
    return {
      membershipId: overrides.membershipId ?? crypto.randomUUID(),
      practiceId: overrides.practiceId ?? practiceId,
      physicianUserId: overrides.physicianUserId ?? crypto.randomUUID(),
      billingMode: overrides.billingMode ?? 'PRACTICE_CONSOLIDATED',
      isActive: true,
      joinedAt: overrides.joinedAt ?? new Date(),
      removedAt: overrides.removedAt ?? new Date(Date.now() - 5 * 24 * 60 * 60 * 1000),
      removalEffectiveAt: overrides.removalEffectiveAt ?? new Date(Date.now() - 1000),
      createdAt: overrides.createdAt ?? new Date(),
    };
  }

  function makePracticeRecord(overrides: Partial<Record<string, any>> = {}) {
    return {
      practiceId: overrides.practiceId ?? practiceId,
      name: overrides.name ?? 'Alpine Family Clinic',
      adminUserId: overrides.adminUserId ?? adminUserId,
      status: overrides.status ?? 'ACTIVE',
      billingFrequency: overrides.billingFrequency ?? 'MONTHLY',
      stripeCustomerId: overrides.stripeCustomerId ?? 'cus_practice_123',
      stripeSubscriptionId: overrides.stripeSubscriptionId ?? 'sub_practice_456',
      currentPeriodStart: new Date(),
      currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  beforeEach(() => {
    auditLogs = [];
    deactivatedMemberships = [];
    deactivatedAllPractices = [];
    stripeSubscriptionUpdates = [];
    stripeCancellations = [];
    stripeCustomersCreated = [];
    stripeSubscriptionsCreated = [];
    subscriptionsCreated = [];
    practiceStatusUpdates = [];
    dissolutionNotifications = [];

    mockPracticeRepo = {
      findPracticeById: vi.fn().mockResolvedValue(makePracticeRecord()),
      findPracticeByAdminUserId: vi.fn(),
      createPractice: vi.fn(),
      updatePractice: vi.fn(),
      getActiveHeadcount: vi.fn().mockResolvedValue(6), // Default: above minimum
      getConsolidatedSeatCount: vi.fn().mockResolvedValue(4),
      updatePracticeStatus: vi.fn().mockImplementation(async (id: string, status: string) => {
        practiceStatusUpdates.push({ practiceId: id, status });
      }),
      findActivePractices: vi.fn(),
    };

    mockMembershipRepo = {
      findActiveMembershipByPhysicianId: vi.fn(),
      findMembershipByPracticeAndPhysician: vi.fn(),
      createMembership: vi.fn(),
      setRemovalScheduled: vi.fn(),
      deactivateMembership: vi.fn().mockImplementation(async (id: string) => {
        deactivatedMemberships.push(id);
      }),
      findPendingRemovals: vi.fn().mockResolvedValue([]),
      deactivateAllMemberships: vi.fn().mockImplementation(async (id: string) => {
        deactivatedAllPractices.push(id);
      }),
      findMembershipsByBillingMode: vi.fn().mockResolvedValue([]),
      countActiveMembersByBillingMode: vi.fn().mockResolvedValue(0),
      updateBillingMode: vi.fn(),
    };

    mockUserRepo = {
      findUserById: vi.fn().mockImplementation(async (userId: string) => {
        if (userId === adminUserId) {
          return {
            userId: adminUserId,
            email: 'admin@example.com',
            fullName: 'Dr. Admin',
            role: 'PRACTICE_ADMIN',
          };
        }
        return {
          userId,
          email: `physician-${userId.slice(0, 6)}@example.com`,
          fullName: `Dr. Physician ${userId.slice(0, 6)}`,
          role: 'PHYSICIAN',
        };
      }),
      findUserByEmail: vi.fn(),
      updateUserRole: vi.fn(),
    };

    mockSubscriptionRepo = {
      findActiveEarlyBirdByProviderId: vi.fn().mockResolvedValue(null),
      findActiveSubscriptionByProviderId: vi.fn().mockResolvedValue(null),
      createSubscription: vi.fn().mockImplementation(async (data: any) => {
        const sub = { subscriptionId: crypto.randomUUID(), ...data };
        subscriptionsCreated.push(sub);
        return sub;
      }),
    };

    mockStripe = {
      customers: {
        create: vi.fn().mockImplementation(async (params: any) => {
          const customer = { id: `cus_${crypto.randomUUID().slice(0, 14)}` };
          stripeCustomersCreated.push({ ...params, result: customer });
          return customer;
        }),
      },
      subscriptions: {
        cancel: vi.fn().mockImplementation(async (subId: string) => {
          stripeCancellations.push(subId);
          return { id: subId, status: 'canceled' };
        }),
        update: vi.fn().mockImplementation(async (subId: string, params: any) => {
          stripeSubscriptionUpdates.push({ subId, ...params });
          return { id: subId, quantity: params.quantity };
        }),
        create: vi.fn().mockImplementation(async (params: any) => {
          const sub = { id: `sub_${crypto.randomUUID().slice(0, 14)}`, status: 'active' };
          stripeSubscriptionsCreated.push({ ...params, result: sub });
          return sub;
        }),
      },
    };

    mockNotifier = {
      sendInvitationEmail: vi.fn(),
      sendRemovalNotification: vi.fn(),
      sendHeadcountWarning: vi.fn(),
      sendDissolutionNotification: vi.fn().mockImplementation(async (params: any) => {
        dissolutionNotifications.push(params);
      }),
    };

    mockAuditLogger = {
      log: vi.fn().mockImplementation(async (entry: any) => {
        auditLogs.push(entry);
      }),
    };

    deps = {
      practiceRepo: mockPracticeRepo,
      membershipRepo: mockMembershipRepo,
      invitationRepo: {} as any,
      userRepo: mockUserRepo,
      subscriptionRepo: mockSubscriptionRepo,
      stripe: mockStripe,
      notifier: mockNotifier,
      auditLogger: mockAuditLogger,
    };
  });

  // -------------------------------------------------------------------------
  // Basic removal processing
  // -------------------------------------------------------------------------

  it('deactivates memberships past their removal_effective_at', async () => {
    const removal = makePendingRemoval();
    mockMembershipRepo.findPendingRemovals.mockResolvedValue([removal]);

    await handleEndOfMonthRemovals(deps);

    expect(deactivatedMemberships).toContain(removal.membershipId);
  });

  it('decrements Stripe quantity for PRACTICE_CONSOLIDATED removals', async () => {
    const removal = makePendingRemoval({ billingMode: 'PRACTICE_CONSOLIDATED' });
    mockMembershipRepo.findPendingRemovals.mockResolvedValue([removal]);
    mockPracticeRepo.getConsolidatedSeatCount.mockResolvedValue(3);

    await handleEndOfMonthRemovals(deps);

    expect(stripeSubscriptionUpdates).toHaveLength(1);
    expect(stripeSubscriptionUpdates[0].subId).toBe('sub_practice_456');
    expect(stripeSubscriptionUpdates[0].quantity).toBe(3);
  });

  it('does not change Stripe quantity for INDIVIDUAL_EARLY_BIRD removals', async () => {
    const removal = makePendingRemoval({ billingMode: 'INDIVIDUAL_EARLY_BIRD' });
    mockMembershipRepo.findPendingRemovals.mockResolvedValue([removal]);

    await handleEndOfMonthRemovals(deps);

    expect(stripeSubscriptionUpdates).toHaveLength(0);
    expect(deactivatedMemberships).toContain(removal.membershipId);
  });

  it('does not dissolve practice when headcount remains at 5 or above', async () => {
    const removal = makePendingRemoval();
    mockMembershipRepo.findPendingRemovals.mockResolvedValue([removal]);
    mockPracticeRepo.getActiveHeadcount.mockResolvedValue(5);

    const result = await handleEndOfMonthRemovals(deps);

    expect(result.dissolvedPractices).toHaveLength(0);
    expect(stripeCancellations).toHaveLength(0);
    expect(practiceStatusUpdates).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // Practice dissolution
  // -------------------------------------------------------------------------

  it('dissolves practice when headcount drops below 5', async () => {
    const removal = makePendingRemoval();
    mockMembershipRepo.findPendingRemovals.mockResolvedValue([removal]);
    mockPracticeRepo.getActiveHeadcount.mockResolvedValue(4);

    const result = await handleEndOfMonthRemovals(deps);

    expect(result.dissolvedPractices).toContain(practiceId);
  });

  it('cancels practice Stripe subscription on dissolution', async () => {
    const removal = makePendingRemoval();
    mockMembershipRepo.findPendingRemovals.mockResolvedValue([removal]);
    mockPracticeRepo.getActiveHeadcount.mockResolvedValue(3);

    await handleEndOfMonthRemovals(deps);

    expect(stripeCancellations).toContain('sub_practice_456');
  });

  it('creates individual STANDARD_MONTHLY subscriptions for PRACTICE_CONSOLIDATED members on MONTHLY practice', async () => {
    const removal = makePendingRemoval();
    const consolidatedMember1 = makePendingRemoval({ billingMode: 'PRACTICE_CONSOLIDATED' });
    const consolidatedMember2 = makePendingRemoval({ billingMode: 'PRACTICE_CONSOLIDATED' });

    mockMembershipRepo.findPendingRemovals.mockResolvedValue([removal]);
    mockPracticeRepo.getActiveHeadcount.mockResolvedValue(3);
    mockPracticeRepo.findPracticeById.mockResolvedValue(
      makePracticeRecord({ billingFrequency: 'MONTHLY' }),
    );
    mockMembershipRepo.findMembershipsByBillingMode.mockImplementation(
      async (_pid: string, billingMode: string) => {
        if (billingMode === 'PRACTICE_CONSOLIDATED') {
          return [consolidatedMember1, consolidatedMember2];
        }
        return [];
      },
    );

    await handleEndOfMonthRemovals(deps);

    expect(subscriptionsCreated).toHaveLength(2);
    for (const sub of subscriptionsCreated) {
      expect(sub.plan).toBe('STANDARD_MONTHLY');
      expect(sub.status).toBe('ACTIVE');
    }
  });

  it('creates individual STANDARD_ANNUAL subscriptions for PRACTICE_CONSOLIDATED members on ANNUAL practice', async () => {
    const removal = makePendingRemoval();
    const consolidatedMember = makePendingRemoval({ billingMode: 'PRACTICE_CONSOLIDATED' });

    mockMembershipRepo.findPendingRemovals.mockResolvedValue([removal]);
    mockPracticeRepo.getActiveHeadcount.mockResolvedValue(2);
    mockPracticeRepo.findPracticeById.mockResolvedValue(
      makePracticeRecord({ billingFrequency: 'ANNUAL' }),
    );
    mockMembershipRepo.findMembershipsByBillingMode.mockImplementation(
      async (_pid: string, billingMode: string) => {
        if (billingMode === 'PRACTICE_CONSOLIDATED') {
          return [consolidatedMember];
        }
        return [];
      },
    );

    await handleEndOfMonthRemovals(deps);

    expect(subscriptionsCreated).toHaveLength(1);
    expect(subscriptionsCreated[0].plan).toBe('STANDARD_ANNUAL');
  });

  it('leaves INDIVIDUAL_EARLY_BIRD subscriptions unchanged on dissolution', async () => {
    const removal = makePendingRemoval();
    const earlyBirdMember = makePendingRemoval({
      billingMode: 'INDIVIDUAL_EARLY_BIRD',
    });

    mockMembershipRepo.findPendingRemovals.mockResolvedValue([removal]);
    mockPracticeRepo.getActiveHeadcount.mockResolvedValue(4);
    mockMembershipRepo.findMembershipsByBillingMode.mockImplementation(
      async (_pid: string, billingMode: string) => {
        if (billingMode === 'INDIVIDUAL_EARLY_BIRD') {
          return [earlyBirdMember];
        }
        return [];
      },
    );

    await handleEndOfMonthRemovals(deps);

    // No new subscriptions created for early bird members
    expect(subscriptionsCreated).toHaveLength(0);
    expect(stripeSubscriptionsCreated).toHaveLength(0);
  });

  it('deactivates all memberships on dissolution', async () => {
    const removal = makePendingRemoval();
    mockMembershipRepo.findPendingRemovals.mockResolvedValue([removal]);
    mockPracticeRepo.getActiveHeadcount.mockResolvedValue(3);

    await handleEndOfMonthRemovals(deps);

    expect(deactivatedAllPractices).toContain(practiceId);
  });

  it('sets practice status to CANCELLED on dissolution', async () => {
    const removal = makePendingRemoval();
    mockMembershipRepo.findPendingRemovals.mockResolvedValue([removal]);
    mockPracticeRepo.getActiveHeadcount.mockResolvedValue(2);

    await handleEndOfMonthRemovals(deps);

    expect(practiceStatusUpdates).toContainEqual({
      practiceId,
      status: 'CANCELLED',
    });
  });

  // -------------------------------------------------------------------------
  // Dissolution notifications
  // -------------------------------------------------------------------------

  it('emits correct notification to PRACTICE_CONSOLIDATED members on dissolution', async () => {
    const consolidatedMember = makePendingRemoval({
      billingMode: 'PRACTICE_CONSOLIDATED',
      physicianUserId: crypto.randomUUID(),
    });
    const removal = makePendingRemoval();

    mockMembershipRepo.findPendingRemovals.mockResolvedValue([removal]);
    mockPracticeRepo.getActiveHeadcount.mockResolvedValue(4);
    mockMembershipRepo.findMembershipsByBillingMode.mockImplementation(
      async (_pid: string, billingMode: string) => {
        if (billingMode === 'PRACTICE_CONSOLIDATED') {
          return [consolidatedMember];
        }
        return [];
      },
    );

    await handleEndOfMonthRemovals(deps);

    const consolidatedNotif = dissolutionNotifications.find(
      (n: any) => n.billingMode === 'PRACTICE_CONSOLIDATED',
    );
    expect(consolidatedNotif).toBeDefined();
    expect(consolidatedNotif.practiceName).toBe('Alpine Family Clinic');
    expect(consolidatedNotif.newPlan).toBe('STANDARD_MONTHLY');
  });

  it('emits correct notification to INDIVIDUAL_EARLY_BIRD members on dissolution', async () => {
    const earlyBirdMember = makePendingRemoval({
      billingMode: 'INDIVIDUAL_EARLY_BIRD',
      physicianUserId: crypto.randomUUID(),
    });
    const removal = makePendingRemoval();

    mockMembershipRepo.findPendingRemovals.mockResolvedValue([removal]);
    mockPracticeRepo.getActiveHeadcount.mockResolvedValue(4);
    mockMembershipRepo.findMembershipsByBillingMode.mockImplementation(
      async (_pid: string, billingMode: string) => {
        if (billingMode === 'INDIVIDUAL_EARLY_BIRD') {
          return [earlyBirdMember];
        }
        return [];
      },
    );

    await handleEndOfMonthRemovals(deps);

    const earlyBirdNotif = dissolutionNotifications.find(
      (n: any) => n.billingMode === 'INDIVIDUAL_EARLY_BIRD',
    );
    expect(earlyBirdNotif).toBeDefined();
    expect(earlyBirdNotif.practiceName).toBe('Alpine Family Clinic');
    expect(earlyBirdNotif.newPlan).toBeUndefined();
  });

  it('emits notification to admin on dissolution', async () => {
    const removal = makePendingRemoval();
    mockMembershipRepo.findPendingRemovals.mockResolvedValue([removal]);
    mockPracticeRepo.getActiveHeadcount.mockResolvedValue(3);

    await handleEndOfMonthRemovals(deps);

    const adminNotif = dissolutionNotifications.find(
      (n: any) => n.billingMode === 'ADMIN',
    );
    expect(adminNotif).toBeDefined();
    expect(adminNotif.toEmail).toBe('admin@example.com');
    expect(adminNotif.practiceName).toBe('Alpine Family Clinic');
  });

  // -------------------------------------------------------------------------
  // Audit logging
  // -------------------------------------------------------------------------

  it('audit logs dissolution with reason', async () => {
    const removal = makePendingRemoval();
    mockMembershipRepo.findPendingRemovals.mockResolvedValue([removal]);
    mockPracticeRepo.getActiveHeadcount.mockResolvedValue(4);

    await handleEndOfMonthRemovals(deps);

    const dissolutionLog = auditLogs.find(
      (l: any) => l.action === 'practice.dissolved',
    );
    expect(dissolutionLog).toBeDefined();
    expect(dissolutionLog).toEqual(
      expect.objectContaining({
        action: 'practice.dissolved',
        resourceType: 'practice',
        resourceId: practiceId,
        actorType: 'system',
        metadata: expect.objectContaining({
          reason: 'BELOW_MINIMUM_HEADCOUNT',
          remainingMemberCount: 4,
          minimumRequired: 5,
        }),
      }),
    );
  });

  // -------------------------------------------------------------------------
  // Multiple practices
  // -------------------------------------------------------------------------

  it('processes removals from multiple practices in one run', async () => {
    const practice2Id = crypto.randomUUID();
    const removal1 = makePendingRemoval({ practiceId });
    const removal2 = makePendingRemoval({ practiceId: practice2Id });

    mockMembershipRepo.findPendingRemovals.mockResolvedValue([removal1, removal2]);
    mockPracticeRepo.findPracticeById.mockImplementation(async (id: string) => {
      if (id === practiceId) return makePracticeRecord({ practiceId });
      if (id === practice2Id) return makePracticeRecord({
        practiceId: practice2Id,
        name: 'Second Clinic',
        stripeSubscriptionId: 'sub_practice2_789',
      });
      return null;
    });
    // Both practices remain above minimum
    mockPracticeRepo.getActiveHeadcount.mockResolvedValue(6);

    const result = await handleEndOfMonthRemovals(deps);

    expect(result.processedCount).toBe(2);
    expect(deactivatedMemberships).toHaveLength(2);
    expect(deactivatedMemberships).toContain(removal1.membershipId);
    expect(deactivatedMemberships).toContain(removal2.membershipId);
  });

  // -------------------------------------------------------------------------
  // Return values
  // -------------------------------------------------------------------------

  it('returns correct processedCount and dissolvedPractices', async () => {
    const removal1 = makePendingRemoval();
    const removal2 = makePendingRemoval();

    mockMembershipRepo.findPendingRemovals.mockResolvedValue([removal1, removal2]);
    mockPracticeRepo.getActiveHeadcount.mockResolvedValue(3);

    const result = await handleEndOfMonthRemovals(deps);

    expect(result.processedCount).toBe(2);
    expect(result.dissolvedPractices).toEqual([practiceId]);
  });

  it('returns zero counts when no pending removals', async () => {
    mockMembershipRepo.findPendingRemovals.mockResolvedValue([]);

    const result = await handleEndOfMonthRemovals(deps);

    expect(result.processedCount).toBe(0);
    expect(result.dissolvedPractices).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // All INDIVIDUAL_EARLY_BIRD dissolution
  // -------------------------------------------------------------------------

  it('handles practice with all INDIVIDUAL_EARLY_BIRD members correctly on dissolution', async () => {
    const earlyBird1 = makePendingRemoval({
      billingMode: 'INDIVIDUAL_EARLY_BIRD',
      physicianUserId: crypto.randomUUID(),
    });
    const earlyBird2 = makePendingRemoval({
      billingMode: 'INDIVIDUAL_EARLY_BIRD',
      physicianUserId: crypto.randomUUID(),
    });
    const removal = makePendingRemoval({ billingMode: 'INDIVIDUAL_EARLY_BIRD' });

    mockMembershipRepo.findPendingRemovals.mockResolvedValue([removal]);
    mockPracticeRepo.getActiveHeadcount.mockResolvedValue(3);
    mockPracticeRepo.findPracticeById.mockResolvedValue(
      makePracticeRecord({ stripeSubscriptionId: 'sub_practice_456' }),
    );
    mockMembershipRepo.findMembershipsByBillingMode.mockImplementation(
      async (_pid: string, billingMode: string) => {
        if (billingMode === 'PRACTICE_CONSOLIDATED') return [];
        if (billingMode === 'INDIVIDUAL_EARLY_BIRD') return [earlyBird1, earlyBird2];
        return [];
      },
    );

    await handleEndOfMonthRemovals(deps);

    // No new individual subscriptions created (they already have their own)
    expect(subscriptionsCreated).toHaveLength(0);
    expect(stripeSubscriptionsCreated).toHaveLength(0);

    // Practice subscription cancelled
    expect(stripeCancellations).toContain('sub_practice_456');

    // Practice status set to CANCELLED
    expect(practiceStatusUpdates).toContainEqual({
      practiceId,
      status: 'CANCELLED',
    });

    // All memberships deactivated
    expect(deactivatedAllPractices).toContain(practiceId);

    // Notifications sent to early bird members
    const earlyBirdNotifs = dissolutionNotifications.filter(
      (n: any) => n.billingMode === 'INDIVIDUAL_EARLY_BIRD',
    );
    expect(earlyBirdNotifs).toHaveLength(2);
  });
});

// ===========================================================================
// getPracticeSeats
// ===========================================================================

describe('getPracticeSeats', () => {
  const adminUserId = crypto.randomUUID();
  const practiceId = crypto.randomUUID();
  let deps: PracticeServiceDeps;
  let mockPracticeRepo: any;
  let mockMembershipRepo: any;
  let mockUserRepo: PracticeUserRepo;
  let userStore: Record<string, { userId: string; email: string; fullName: string; role: string }>;

  beforeEach(() => {
    userStore = {};

    const adminUser = {
      userId: adminUserId,
      email: 'admin@clinic.ca',
      fullName: 'Dr. Admin',
      role: 'PHYSICIAN',
    };
    userStore[adminUserId] = adminUser;

    mockUserRepo = {
      findUserById: vi.fn().mockImplementation(async (userId: string) => {
        return userStore[userId] ?? undefined;
      }),
      findUserByEmail: vi.fn().mockResolvedValue(undefined),
      updateUserRole: vi.fn(),
    };

    mockPracticeRepo = {
      findPracticeById: vi.fn().mockResolvedValue({
        practiceId,
        name: 'Test Clinic',
        adminUserId,
        billingFrequency: 'MONTHLY',
        status: 'ACTIVE',
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        stripeCustomerId: 'cus_test',
        stripeSubscriptionId: 'sub_test',
        createdAt: new Date(),
        updatedAt: new Date(),
      }),
      getConsolidatedSeatCount: vi.fn().mockResolvedValue(3),
      getActiveHeadcount: vi.fn().mockResolvedValue(5),
    };

    const physician1Id = crypto.randomUUID();
    const physician2Id = crypto.randomUUID();
    const physician3Id = crypto.randomUUID();

    userStore[physician1Id] = {
      userId: physician1Id,
      email: 'dr.one@clinic.ca',
      fullName: 'Dr. One',
      role: 'PHYSICIAN',
    };
    userStore[physician2Id] = {
      userId: physician2Id,
      email: 'dr.two@clinic.ca',
      fullName: 'Dr. Two',
      role: 'PHYSICIAN',
    };
    userStore[physician3Id] = {
      userId: physician3Id,
      email: 'dr.three@clinic.ca',
      fullName: 'Dr. Three',
      role: 'PHYSICIAN',
    };

    const joinedAt1 = new Date('2026-01-15');
    const joinedAt2 = new Date('2026-02-01');
    const joinedAt3 = new Date('2026-02-10');

    mockMembershipRepo = {
      findActiveMembershipsByPracticeId: vi.fn().mockResolvedValue([
        {
          membershipId: crypto.randomUUID(),
          practiceId,
          physicianUserId: physician1Id,
          billingMode: 'PRACTICE_CONSOLIDATED',
          joinedAt: joinedAt1,
          isActive: true,
          removedAt: null,
          removalEffectiveAt: null,
        },
        {
          membershipId: crypto.randomUUID(),
          practiceId,
          physicianUserId: physician2Id,
          billingMode: 'INDIVIDUAL_EARLY_BIRD',
          joinedAt: joinedAt2,
          isActive: true,
          removedAt: null,
          removalEffectiveAt: null,
        },
        {
          membershipId: crypto.randomUUID(),
          practiceId,
          physicianUserId: physician3Id,
          billingMode: 'PRACTICE_CONSOLIDATED',
          joinedAt: joinedAt3,
          isActive: true,
          removedAt: null,
          removalEffectiveAt: null,
        },
      ]),
      findActiveMembershipByPhysicianId: vi.fn().mockResolvedValue(null),
    };

    deps = {
      practiceRepo: mockPracticeRepo,
      membershipRepo: mockMembershipRepo,
      invitationRepo: {} as any,
      userRepo: mockUserRepo,
      subscriptionRepo: { findActiveEarlyBirdByProviderId: vi.fn().mockResolvedValue(null) },
      stripe: { customers: { create: vi.fn() } },
    };
  });

  it('returns list of active members with name, email, joinedAt, billingMode', async () => {
    const seats = await getPracticeSeats(deps, practiceId, adminUserId);

    expect(seats).toHaveLength(3);
    expect(seats[0].physicianName).toBe('Dr. One');
    expect(seats[0].email).toBe('dr.one@clinic.ca');
    expect(seats[0].joinedAt).toBeInstanceOf(Date);
    expect(seats[0].billingMode).toBe('PRACTICE_CONSOLIDATED');
  });

  it('returns ONLY physicianName, email, joinedAt, billingMode per seat', async () => {
    const seats = await getPracticeSeats(deps, practiceId, adminUserId);

    for (const seat of seats) {
      const keys = Object.keys(seat);
      expect(keys).toHaveLength(4);
      expect(keys).toContain('physicianName');
      expect(keys).toContain('email');
      expect(keys).toContain('joinedAt');
      expect(keys).toContain('billingMode');
    }
  });

  it('does NOT return claim counts', async () => {
    const seats = await getPracticeSeats(deps, practiceId, adminUserId);
    for (const seat of seats) {
      expect(seat).not.toHaveProperty('claimCount');
      expect(seat).not.toHaveProperty('claims');
    }
  });

  it('does NOT return billing volumes', async () => {
    const seats = await getPracticeSeats(deps, practiceId, adminUserId);
    for (const seat of seats) {
      expect(seat).not.toHaveProperty('billingVolume');
      expect(seat).not.toHaveProperty('revenue');
      expect(seat).not.toHaveProperty('totalBilled');
    }
  });

  it('does NOT return rejection rates', async () => {
    const seats = await getPracticeSeats(deps, practiceId, adminUserId);
    for (const seat of seats) {
      expect(seat).not.toHaveProperty('rejectionRate');
      expect(seat).not.toHaveProperty('rejections');
    }
  });

  it('does NOT return patient data', async () => {
    const seats = await getPracticeSeats(deps, practiceId, adminUserId);
    for (const seat of seats) {
      expect(seat).not.toHaveProperty('patientCount');
      expect(seat).not.toHaveProperty('patients');
    }
  });

  it('does NOT return analytics data', async () => {
    const seats = await getPracticeSeats(deps, practiceId, adminUserId);
    for (const seat of seats) {
      expect(seat).not.toHaveProperty('analytics');
      expect(seat).not.toHaveProperty('dashboardData');
    }
  });

  it('does NOT return individual payment history', async () => {
    const seats = await getPracticeSeats(deps, practiceId, adminUserId);
    for (const seat of seats) {
      expect(seat).not.toHaveProperty('paymentHistory');
      expect(seat).not.toHaveProperty('payments');
      expect(seat).not.toHaveProperty('invoices');
    }
  });

  it('does NOT return individual subscription details', async () => {
    const seats = await getPracticeSeats(deps, practiceId, adminUserId);
    for (const seat of seats) {
      expect(seat).not.toHaveProperty('subscription');
      expect(seat).not.toHaveProperty('subscriptionPlan');
      expect(seat).not.toHaveProperty('subscriptionStatus');
    }
  });

  it('rejects if caller is not PRACTICE_ADMIN', async () => {
    const otherUserId = crypto.randomUUID();
    await expect(
      getPracticeSeats(deps, practiceId, otherUserId),
    ).rejects.toThrow('Not a practice admin');
  });

  it('excludes inactive members', async () => {
    // The mock returns only active memberships (findActiveMembershipsByPracticeId)
    // which already filters by isActive = true. Verify the repo method is called.
    await getPracticeSeats(deps, practiceId, adminUserId);
    expect(mockMembershipRepo.findActiveMembershipsByPracticeId).toHaveBeenCalledWith(practiceId);
  });

  it('includes both PRACTICE_CONSOLIDATED and INDIVIDUAL_EARLY_BIRD members', async () => {
    const seats = await getPracticeSeats(deps, practiceId, adminUserId);

    const billingModes = seats.map((s) => s.billingMode);
    expect(billingModes).toContain('PRACTICE_CONSOLIDATED');
    expect(billingModes).toContain('INDIVIDUAL_EARLY_BIRD');
  });

  it('throws NotFoundError when practice does not exist', async () => {
    mockPracticeRepo.findPracticeById = vi.fn().mockResolvedValue(null);
    await expect(
      getPracticeSeats(deps, practiceId, adminUserId),
    ).rejects.toThrow('not found');
  });
});

// ===========================================================================
// getPracticeInvoice
// ===========================================================================

describe('getPracticeInvoice', () => {
  const adminUserId = crypto.randomUUID();
  const practiceId = crypto.randomUUID();
  const nextMonth = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  let deps: PracticeServiceDeps;
  let mockPracticeRepo: any;

  beforeEach(() => {
    mockPracticeRepo = {
      findPracticeById: vi.fn().mockResolvedValue({
        practiceId,
        name: 'Test Clinic',
        adminUserId,
        billingFrequency: 'MONTHLY',
        status: 'ACTIVE',
        currentPeriodStart: new Date(),
        currentPeriodEnd: nextMonth,
        stripeCustomerId: 'cus_test',
        stripeSubscriptionId: 'sub_test',
        createdAt: new Date(),
        updatedAt: new Date(),
      }),
      getConsolidatedSeatCount: vi.fn().mockResolvedValue(3),
      getActiveHeadcount: vi.fn().mockResolvedValue(5),
    };

    deps = {
      practiceRepo: mockPracticeRepo,
      membershipRepo: {
        findActiveMembershipsByPracticeId: vi.fn().mockResolvedValue([]),
        findActiveMembershipByPhysicianId: vi.fn().mockResolvedValue(null),
      } as any,
      invitationRepo: {} as any,
      userRepo: {
        findUserById: vi.fn().mockResolvedValue(undefined),
        findUserByEmail: vi.fn().mockResolvedValue(undefined),
        updateUserRole: vi.fn(),
      },
      subscriptionRepo: { findActiveEarlyBirdByProviderId: vi.fn().mockResolvedValue(null) },
      stripe: { customers: { create: vi.fn() } },
    };
  });

  it('returns consolidated invoice with correct totalAmount', async () => {
    // 3 consolidated seats * $251.10 = $753.30
    const invoice = await getPracticeInvoice(deps, practiceId, adminUserId);
    expect(invoice.totalAmount).toBe('753.30');
  });

  it('returns correct perSeatRate for MONTHLY billing', async () => {
    const invoice = await getPracticeInvoice(deps, practiceId, adminUserId);
    expect(invoice.perSeatRate).toBe('251.10');
  });

  it('returns correct perSeatRate for ANNUAL billing', async () => {
    mockPracticeRepo.findPracticeById = vi.fn().mockResolvedValue({
      practiceId,
      name: 'Test Clinic',
      adminUserId,
      billingFrequency: 'ANNUAL',
      status: 'ACTIVE',
      currentPeriodStart: new Date(),
      currentPeriodEnd: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
      stripeCustomerId: 'cus_test',
      stripeSubscriptionId: 'sub_test',
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const invoice = await getPracticeInvoice(deps, practiceId, adminUserId);
    // $2863.00 / 12 = $238.58 (rounded)
    expect(invoice.perSeatRate).toBe('238.58');
    expect(invoice.billingFrequency).toBe('ANNUAL');
  });

  it('returns correct consolidatedSeatCount (only PRACTICE_CONSOLIDATED)', async () => {
    const invoice = await getPracticeInvoice(deps, practiceId, adminUserId);
    expect(invoice.consolidatedSeatCount).toBe(3);
    expect(mockPracticeRepo.getConsolidatedSeatCount).toHaveBeenCalledWith(practiceId);
  });

  it('returns correct totalHeadcount (all billing modes)', async () => {
    const invoice = await getPracticeInvoice(deps, practiceId, adminUserId);
    expect(invoice.totalHeadcount).toBe(5);
    expect(mockPracticeRepo.getActiveHeadcount).toHaveBeenCalledWith(practiceId);
  });

  it('returns correct gstAmount', async () => {
    // $753.30 * 0.05 = $37.665 → toFixed(2) = '37.66' (IEEE 754 rounding)
    const invoice = await getPracticeInvoice(deps, practiceId, adminUserId);
    expect(invoice.gstAmount).toBe('37.66');
  });

  it('returns nextInvoiceDate', async () => {
    const invoice = await getPracticeInvoice(deps, practiceId, adminUserId);
    expect(invoice.nextInvoiceDate).toEqual(nextMonth);
  });

  it('rejects if caller is not PRACTICE_ADMIN', async () => {
    const otherUserId = crypto.randomUUID();
    await expect(
      getPracticeInvoice(deps, practiceId, otherUserId),
    ).rejects.toThrow('Not a practice admin');
  });

  it('does NOT return individual physician payment records', async () => {
    const invoice = await getPracticeInvoice(deps, practiceId, adminUserId);
    expect(invoice).not.toHaveProperty('physicianPayments');
    expect(invoice).not.toHaveProperty('individualInvoices');
    expect(invoice).not.toHaveProperty('paymentHistory');

    // Verify only the 4+3 expected keys
    const keys = Object.keys(invoice);
    expect(keys).toHaveLength(7);
    expect(keys).toEqual(expect.arrayContaining([
      'totalAmount',
      'perSeatRate',
      'consolidatedSeatCount',
      'totalHeadcount',
      'billingFrequency',
      'nextInvoiceDate',
      'gstAmount',
    ]));
  });

  it('throws NotFoundError when practice does not exist', async () => {
    mockPracticeRepo.findPracticeById = vi.fn().mockResolvedValue(null);
    await expect(
      getPracticeInvoice(deps, practiceId, adminUserId),
    ).rejects.toThrow('not found');
  });

  it('returns totalAmount of 0.00 when no consolidated seats', async () => {
    mockPracticeRepo.getConsolidatedSeatCount = vi.fn().mockResolvedValue(0);
    const invoice = await getPracticeInvoice(deps, practiceId, adminUserId);
    expect(invoice.totalAmount).toBe('0.00');
    expect(invoice.gstAmount).toBe('0.00');
    expect(invoice.consolidatedSeatCount).toBe(0);
  });

  it('returns correct annual totalAmount', async () => {
    mockPracticeRepo.findPracticeById = vi.fn().mockResolvedValue({
      practiceId,
      name: 'Test Clinic',
      adminUserId,
      billingFrequency: 'ANNUAL',
      status: 'ACTIVE',
      currentPeriodStart: new Date(),
      currentPeriodEnd: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
      stripeCustomerId: 'cus_test',
      stripeSubscriptionId: 'sub_test',
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    // 3 consolidated seats * $2863.00 = $8589.00
    const invoice = await getPracticeInvoice(deps, practiceId, adminUserId);
    expect(invoice.totalAmount).toBe('8589.00');
    expect(invoice.gstAmount).toBe('429.45');
  });
});

// ===========================================================================
// Practice Handlers — wiring tests
// ===========================================================================

describe('Practice Handlers', () => {
  // -------------------------------------------------------------------------
  // Shared mock reply helper
  // -------------------------------------------------------------------------

  function makeMockReply() {
    const reply: any = {
      _statusCode: 200,
      _body: undefined,
      code(c: number) { reply._statusCode = c; return reply; },
      send(body?: any) { reply._body = body; return reply; },
    };
    return reply;
  }

  // -------------------------------------------------------------------------
  // Shared mock service deps that satisfy the handler's needs
  // -------------------------------------------------------------------------

  const mockPractice = {
    practiceId: crypto.randomUUID(),
    name: 'Handler Test Clinic',
    adminUserId: crypto.randomUUID(),
    billingFrequency: 'MONTHLY',
    status: 'ACTIVE',
    stripeCustomerId: 'cus_handler',
    stripeSubscriptionId: null,
    currentPeriodStart: new Date(),
    currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockMembership = {
    membershipId: crypto.randomUUID(),
    practiceId: mockPractice.practiceId,
    physicianUserId: crypto.randomUUID(),
    billingMode: 'PRACTICE_CONSOLIDATED',
    joinedAt: new Date(),
    removedAt: null,
    removalEffectiveAt: null,
    isActive: true,
    createdAt: new Date(),
  };

  const mockInvitation = {
    invitationId: crypto.randomUUID(),
    practiceId: mockPractice.practiceId,
    invitedEmail: 'invited@example.com',
    invitedByUserId: mockPractice.adminUserId,
    status: 'PENDING',
    tokenHash: 'hashedtoken123',
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    createdAt: new Date(),
  };

  // Build handler deps with mocked practiceRepo and service deps
  let handlerDeps: PracticeHandlerDeps;
  let handlers: ReturnType<typeof createPracticeHandlers>;

  beforeEach(() => {
    const mockPracticeRepo: any = {
      findPracticeById: vi.fn().mockResolvedValue(mockPractice),
      updatePractice: vi.fn().mockResolvedValue({ ...mockPractice, name: 'Updated' }),
      createPractice: vi.fn().mockResolvedValue(mockPractice),
      findPracticeByAdminUserId: vi.fn().mockResolvedValue(null),
      getActiveHeadcount: vi.fn().mockResolvedValue(5),
      getConsolidatedSeatCount: vi.fn().mockResolvedValue(3),
      updatePracticeStatus: vi.fn().mockResolvedValue(undefined),
      updatePracticeStripeIds: vi.fn().mockResolvedValue(undefined),
      findActivePractices: vi.fn().mockResolvedValue([]),
    };

    const mockMembershipRepo: any = {
      createMembership: vi.fn().mockResolvedValue(mockMembership),
      findActiveMembershipByPhysicianId: vi.fn().mockResolvedValue(null),
      findMembershipByPracticeAndPhysician: vi.fn().mockResolvedValue(null),
      findActiveMembershipsByPracticeId: vi.fn().mockResolvedValue([mockMembership]),
      setRemovalScheduled: vi.fn().mockResolvedValue(undefined),
      findPendingRemovals: vi.fn().mockResolvedValue([]),
      deactivateMembership: vi.fn().mockResolvedValue(undefined),
      deactivateAllMemberships: vi.fn().mockResolvedValue(undefined),
      findMembershipsByBillingMode: vi.fn().mockResolvedValue([]),
    };

    const mockInvitationRepo: any = {
      createInvitation: vi.fn().mockResolvedValue(mockInvitation),
      findPendingInvitationByEmail: vi.fn().mockResolvedValue(null),
      findInvitationByTokenHash: vi.fn().mockResolvedValue(null),
      updateInvitationStatus: vi.fn().mockResolvedValue(undefined),
    };

    const mockUserRepo: PracticeUserRepo = {
      findUserById: vi.fn().mockResolvedValue({
        userId: mockPractice.adminUserId,
        email: 'admin@example.com',
        fullName: 'Dr Admin',
        role: 'PHYSICIAN',
      }),
      findUserByEmail: vi.fn().mockResolvedValue(null),
      updateUserRole: vi.fn().mockResolvedValue(undefined),
    };

    const mockSubRepo: PracticeSubscriptionRepo = {
      findActiveEarlyBirdByProviderId: vi.fn().mockResolvedValue(null),
    };

    const mockStripe: PracticeStripeClient = {
      customers: {
        create: vi.fn().mockResolvedValue({ id: 'cus_new' }),
      },
    };

    handlerDeps = {
      serviceDeps: {
        practiceRepo: mockPracticeRepo,
        membershipRepo: mockMembershipRepo,
        invitationRepo: mockInvitationRepo,
        userRepo: mockUserRepo,
        subscriptionRepo: mockSubRepo,
        stripe: mockStripe,
        auditLogger: { log: vi.fn().mockResolvedValue(undefined) },
      },
      practiceRepo: mockPracticeRepo,
    };

    handlers = createPracticeHandlers(handlerDeps);
  });

  it('createPracticeHandler returns 201 with practice data', async () => {
    const request: any = {
      authContext: { userId: mockPractice.adminUserId },
      body: { name: 'Handler Test Clinic', billing_frequency: 'MONTHLY' },
    };
    const reply = makeMockReply();

    await handlers.createPracticeHandler(request, reply);

    expect(reply._statusCode).toBe(201);
    expect(reply._body).toHaveProperty('data');
    expect(reply._body.data.practiceId).toBeDefined();
  });

  it('getPracticeHandler returns 200 with practice data', async () => {
    const request: any = {
      authContext: { userId: mockPractice.adminUserId },
      params: { id: mockPractice.practiceId },
    };
    const reply = makeMockReply();

    await handlers.getPracticeHandler(request, reply);

    expect(reply._statusCode).toBe(200);
    expect(reply._body).toHaveProperty('data');
    expect(reply._body.data.practiceId).toBe(mockPractice.practiceId);
  });

  it('getPracticeHandler returns 404 when practice not found', async () => {
    (handlerDeps.practiceRepo.findPracticeById as any).mockResolvedValue(null);

    const request: any = {
      authContext: { userId: mockPractice.adminUserId },
      params: { id: crypto.randomUUID() },
    };
    const reply = makeMockReply();

    await handlers.getPracticeHandler(request, reply);

    expect(reply._statusCode).toBe(404);
    expect(reply._body.error.code).toBe('NOT_FOUND');
  });

  it('updatePracticeHandler returns 200 with updated practice', async () => {
    const request: any = {
      authContext: { userId: mockPractice.adminUserId },
      params: { id: mockPractice.practiceId },
      body: { name: 'Updated Clinic' },
    };
    const reply = makeMockReply();

    await handlers.updatePracticeHandler(request, reply);

    expect(reply._statusCode).toBe(200);
    expect(reply._body).toHaveProperty('data');
  });

  it('getPracticeSeatsHandler returns 200 with seats array', async () => {
    const request: any = {
      authContext: { userId: mockPractice.adminUserId },
      params: { id: mockPractice.practiceId },
      query: { page: 1, page_size: 50 },
    };
    const reply = makeMockReply();

    await handlers.getPracticeSeatsHandler(request, reply);

    expect(reply._statusCode).toBe(200);
    expect(reply._body).toHaveProperty('data');
    expect(reply._body).toHaveProperty('pagination');
    expect(Array.isArray(reply._body.data)).toBe(true);
  });

  it('getPracticeSeatsHandler does not add extra fields to response', async () => {
    const request: any = {
      authContext: { userId: mockPractice.adminUserId },
      params: { id: mockPractice.practiceId },
      query: { page: 1, page_size: 50 },
    };
    const reply = makeMockReply();

    await handlers.getPracticeSeatsHandler(request, reply);

    expect(reply._statusCode).toBe(200);
    const responseKeys = Object.keys(reply._body);
    expect(responseKeys).toEqual(expect.arrayContaining(['data', 'pagination']));
    expect(responseKeys.length).toBe(2);

    // Each seat should only have the four allowed fields
    for (const seat of reply._body.data) {
      const seatKeys = Object.keys(seat);
      expect(seatKeys.sort()).toEqual(
        ['billingMode', 'email', 'joinedAt', 'physicianName'].sort(),
      );
    }
  });

  it('invitePhysicianHandler returns 201 without raw token', async () => {
    // Override service deps to make invitePhysician work through the service path
    const invReq: any = {
      authContext: { userId: mockPractice.adminUserId },
      params: { id: mockPractice.practiceId },
      body: { email: 'invited@example.com' },
    };
    const reply = makeMockReply();

    await handlers.invitePhysicianHandler(invReq, reply);

    expect(reply._statusCode).toBe(201);
    expect(reply._body).toHaveProperty('data');
    // The invitation record from service should not contain a raw token field
    const data = reply._body.data;
    expect(data).not.toHaveProperty('rawToken');
    expect(data).not.toHaveProperty('token');
    expect(data.invitationId).toBeDefined();
  });

  it('acceptInvitationHandler returns 200 with membership', async () => {
    // Set up the invitation repo to return a valid invitation
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const acceptingUserId = crypto.randomUUID();

    const pendingInvitation = {
      ...mockInvitation,
      tokenHash,
      invitedEmail: 'accepting@example.com',
      status: 'PENDING',
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    };

    (handlerDeps.serviceDeps.invitationRepo.findInvitationByTokenHash as any)
      .mockResolvedValue(pendingInvitation);
    (handlerDeps.serviceDeps.userRepo.findUserById as any)
      .mockResolvedValue({
        userId: acceptingUserId,
        email: 'accepting@example.com',
        fullName: 'Dr Accepting',
        role: 'PHYSICIAN',
      });
    (handlerDeps.serviceDeps.membershipRepo.findActiveMembershipByPhysicianId as any)
      .mockResolvedValue(null);

    const request: any = {
      authContext: { userId: acceptingUserId },
      params: { token: rawToken },
    };
    const reply = makeMockReply();

    await handlers.acceptInvitationHandler(request, reply);

    expect(reply._statusCode).toBe(200);
    expect(reply._body).toHaveProperty('data');
    expect(reply._body.data.membershipId).toBeDefined();
  });

  it('removePhysicianHandler returns 204', async () => {
    const physicianToRemove = crypto.randomUUID();

    // Set up mocks so removePhysician service succeeds
    (handlerDeps.serviceDeps.practiceRepo.findPracticeById as any)
      .mockResolvedValue(mockPractice);
    (handlerDeps.serviceDeps.membershipRepo.findMembershipByPracticeAndPhysician as any)
      .mockResolvedValue({
        ...mockMembership,
        physicianUserId: physicianToRemove,
        removalEffectiveAt: null,
      });

    const request: any = {
      authContext: { userId: mockPractice.adminUserId },
      params: { id: mockPractice.practiceId, userId: physicianToRemove },
    };
    const reply = makeMockReply();

    await handlers.removePhysicianHandler(request, reply);

    expect(reply._statusCode).toBe(204);
  });

  it('getPracticeInvoicesHandler returns 200 with invoice data', async () => {
    const request: any = {
      authContext: { userId: mockPractice.adminUserId },
      params: { id: mockPractice.practiceId },
      query: { page: 1, page_size: 10 },
    };
    const reply = makeMockReply();

    await handlers.getPracticeInvoicesHandler(request, reply);

    expect(reply._statusCode).toBe(200);
    expect(reply._body).toHaveProperty('data');
    expect(reply._body.data).toHaveProperty('totalAmount');
    expect(reply._body.data).toHaveProperty('perSeatRate');
    expect(reply._body.data).toHaveProperty('consolidatedSeatCount');
    expect(reply._body.data).toHaveProperty('gstAmount');
  });
});
