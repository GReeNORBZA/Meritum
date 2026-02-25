import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createPracticeMembershipRepository } from './practice-membership.repository.js';

// ---------------------------------------------------------------------------
// In-memory store
// ---------------------------------------------------------------------------

let membershipStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Mock Drizzle DB
// ---------------------------------------------------------------------------

function makeMockDb() {
  function getStoreForTable(_table: any): Record<string, any>[] {
    return membershipStore;
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

  function insertRow(_table: any, values: any): any {
    const store = membershipStore;
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

    // Enforce unique partial index: one active membership per physician
    if (newMembership.isActive) {
      const existing = store.find(
        (m) =>
          m.physicianUserId === newMembership.physicianUserId &&
          m.isActive === true,
      );
      if (existing) {
        throw new Error(
          'unique constraint violation: practice_memberships_physician_active_idx',
        );
      }
    }

    store.push(newMembership);
    return newMembership;
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
        __predicate: (row: any) => {
          const rowVal = row[colName];
          if (rowVal == null) return false;
          if (rowVal instanceof Date && value instanceof Date) {
            return rowVal.getTime() <= value.getTime();
          }
          return rowVal <= value;
        },
      };
    },
    count: () => ({ __aggregate: 'count' }),
  };
});

// Mock the schema module
vi.mock('@meritum/shared/schemas/db/platform.schema.js', () => {
  const makeCol = (name: string) => ({ name });

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

  return {
    practiceMemberships: practiceMembershipsProxy,
  };
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DAY_MS = 24 * 60 * 60 * 1000;

function makeMembershipData(overrides: Partial<Record<string, any>> = {}) {
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

describe('PracticeMembershipRepository', () => {
  let repo: ReturnType<typeof createPracticeMembershipRepository>;
  let db: any;

  beforeEach(() => {
    membershipStore = [];
    db = makeMockDb();
    repo = createPracticeMembershipRepository(db);
  });

  // -------------------------------------------------------------------------
  // createMembership
  // -------------------------------------------------------------------------

  it('createMembership inserts and returns a membership record', async () => {
    const data = makeMembershipData();
    const result = await repo.createMembership(data as any);

    expect(result).toBeDefined();
    expect(result.membershipId).toBeDefined();
    expect(result.practiceId).toBe(data.practiceId);
    expect(result.physicianUserId).toBe(data.physicianUserId);
    expect(result.isActive).toBe(true);
    expect(membershipStore).toHaveLength(1);
  });

  it('createMembership defaults billing_mode to PRACTICE_CONSOLIDATED', async () => {
    const data = makeMembershipData();
    delete (data as any).billingMode;
    const result = await repo.createMembership(data as any);

    expect(result.billingMode).toBe('PRACTICE_CONSOLIDATED');
  });

  it('createMembership respects INDIVIDUAL_EARLY_BIRD billing_mode', async () => {
    const data = makeMembershipData({ billingMode: 'INDIVIDUAL_EARLY_BIRD' });
    const result = await repo.createMembership(data as any);

    expect(result.billingMode).toBe('INDIVIDUAL_EARLY_BIRD');
  });

  // -------------------------------------------------------------------------
  // findActiveMembershipByPhysicianId
  // -------------------------------------------------------------------------

  it('findActiveMembershipByPhysicianId returns active membership', async () => {
    const physicianUserId = crypto.randomUUID();
    const data = makeMembershipData({ physicianUserId });
    await repo.createMembership(data as any);

    const found = await repo.findActiveMembershipByPhysicianId(physicianUserId);
    expect(found).toBeDefined();
    expect(found!.physicianUserId).toBe(physicianUserId);
    expect(found!.isActive).toBe(true);
  });

  it('findActiveMembershipByPhysicianId returns null for inactive membership', async () => {
    const physicianUserId = crypto.randomUUID();
    // Insert directly with isActive = false to bypass unique constraint check
    membershipStore.push({
      membershipId: crypto.randomUUID(),
      practiceId: crypto.randomUUID(),
      physicianUserId,
      billingMode: 'PRACTICE_CONSOLIDATED',
      isActive: false,
      joinedAt: new Date(),
      removedAt: null,
      removalEffectiveAt: null,
      createdAt: new Date(),
    });

    const found = await repo.findActiveMembershipByPhysicianId(physicianUserId);
    expect(found).toBeNull();
  });

  it('findActiveMembershipByPhysicianId returns null for non-existent physician', async () => {
    const found = await repo.findActiveMembershipByPhysicianId(crypto.randomUUID());
    expect(found).toBeNull();
  });

  // -------------------------------------------------------------------------
  // findActiveMembershipsByPracticeId
  // -------------------------------------------------------------------------

  it('findActiveMembershipsByPracticeId returns all active members', async () => {
    const practiceId = crypto.randomUUID();
    await repo.createMembership(
      makeMembershipData({ practiceId, physicianUserId: crypto.randomUUID() }) as any,
    );
    await repo.createMembership(
      makeMembershipData({ practiceId, physicianUserId: crypto.randomUUID() }) as any,
    );
    await repo.createMembership(
      makeMembershipData({ practiceId, physicianUserId: crypto.randomUUID() }) as any,
    );

    const members = await repo.findActiveMembershipsByPracticeId(practiceId);
    expect(members).toHaveLength(3);
    for (const m of members) {
      expect(m.practiceId).toBe(practiceId);
      expect(m.isActive).toBe(true);
    }
  });

  it('findActiveMembershipsByPracticeId excludes inactive members', async () => {
    const practiceId = crypto.randomUUID();
    await repo.createMembership(
      makeMembershipData({ practiceId, physicianUserId: crypto.randomUUID() }) as any,
    );
    // Insert inactive member directly
    membershipStore.push({
      membershipId: crypto.randomUUID(),
      practiceId,
      physicianUserId: crypto.randomUUID(),
      billingMode: 'PRACTICE_CONSOLIDATED',
      isActive: false,
      joinedAt: new Date(),
      removedAt: null,
      removalEffectiveAt: null,
      createdAt: new Date(),
    });

    const members = await repo.findActiveMembershipsByPracticeId(practiceId);
    expect(members).toHaveLength(1);
    expect(members[0].isActive).toBe(true);
  });

  // -------------------------------------------------------------------------
  // setRemovalScheduled
  // -------------------------------------------------------------------------

  it('setRemovalScheduled sets removed_at and removal_effective_at', async () => {
    const data = makeMembershipData();
    const created = await repo.createMembership(data as any);

    const removedAt = new Date();
    const removalEffectiveAt = new Date(Date.now() + 30 * DAY_MS);

    await repo.setRemovalScheduled(
      created.membershipId,
      removedAt,
      removalEffectiveAt,
    );

    const stored = membershipStore.find(
      (m) => m.membershipId === created.membershipId,
    );
    expect(stored!.removedAt).toBe(removedAt);
    expect(stored!.removalEffectiveAt).toBe(removalEffectiveAt);
  });

  it('setRemovalScheduled does not set is_active to false', async () => {
    const data = makeMembershipData();
    const created = await repo.createMembership(data as any);

    const removedAt = new Date();
    const removalEffectiveAt = new Date(Date.now() + 30 * DAY_MS);

    await repo.setRemovalScheduled(
      created.membershipId,
      removedAt,
      removalEffectiveAt,
    );

    const stored = membershipStore.find(
      (m) => m.membershipId === created.membershipId,
    );
    expect(stored!.isActive).toBe(true);
  });

  // -------------------------------------------------------------------------
  // deactivateMembership
  // -------------------------------------------------------------------------

  it('deactivateMembership sets is_active to false', async () => {
    const data = makeMembershipData();
    const created = await repo.createMembership(data as any);

    await repo.deactivateMembership(created.membershipId);

    const stored = membershipStore.find(
      (m) => m.membershipId === created.membershipId,
    );
    expect(stored!.isActive).toBe(false);
  });

  // -------------------------------------------------------------------------
  // findPendingRemovals
  // -------------------------------------------------------------------------

  it('findPendingRemovals returns memberships past cutoff date', async () => {
    const practiceId = crypto.randomUUID();
    const pastDate = new Date(Date.now() - 5 * DAY_MS);
    const futureDate = new Date(Date.now() + 5 * DAY_MS);

    // Active membership with past removal effective date
    membershipStore.push({
      membershipId: crypto.randomUUID(),
      practiceId,
      physicianUserId: crypto.randomUUID(),
      billingMode: 'PRACTICE_CONSOLIDATED',
      isActive: true,
      joinedAt: new Date(),
      removedAt: new Date(Date.now() - 35 * DAY_MS),
      removalEffectiveAt: pastDate,
      createdAt: new Date(),
    });

    // Active membership with future removal effective date (not yet due)
    membershipStore.push({
      membershipId: crypto.randomUUID(),
      practiceId,
      physicianUserId: crypto.randomUUID(),
      billingMode: 'PRACTICE_CONSOLIDATED',
      isActive: true,
      joinedAt: new Date(),
      removedAt: new Date(),
      removalEffectiveAt: futureDate,
      createdAt: new Date(),
    });

    const cutoff = new Date();
    const pending = await repo.findPendingRemovals(cutoff);
    expect(pending).toHaveLength(1);
    expect(pending[0].removalEffectiveAt.getTime()).toBeLessThanOrEqual(
      cutoff.getTime(),
    );
  });

  it('findPendingRemovals excludes already deactivated memberships', async () => {
    const practiceId = crypto.randomUUID();
    const pastDate = new Date(Date.now() - 5 * DAY_MS);

    // Inactive membership with past removal effective date
    membershipStore.push({
      membershipId: crypto.randomUUID(),
      practiceId,
      physicianUserId: crypto.randomUUID(),
      billingMode: 'PRACTICE_CONSOLIDATED',
      isActive: false,
      joinedAt: new Date(),
      removedAt: new Date(Date.now() - 35 * DAY_MS),
      removalEffectiveAt: pastDate,
      createdAt: new Date(),
    });

    const cutoff = new Date();
    const pending = await repo.findPendingRemovals(cutoff);
    expect(pending).toHaveLength(0);
  });

  // -------------------------------------------------------------------------
  // deactivateAllMemberships
  // -------------------------------------------------------------------------

  it('deactivateAllMemberships deactivates all active members on practice', async () => {
    const practiceId = crypto.randomUUID();
    await repo.createMembership(
      makeMembershipData({ practiceId, physicianUserId: crypto.randomUUID() }) as any,
    );
    await repo.createMembership(
      makeMembershipData({ practiceId, physicianUserId: crypto.randomUUID() }) as any,
    );
    await repo.createMembership(
      makeMembershipData({ practiceId, physicianUserId: crypto.randomUUID() }) as any,
    );

    // Verify all are active before
    expect(membershipStore.filter((m) => m.isActive).length).toBe(3);

    await repo.deactivateAllMemberships(practiceId);

    // All memberships for this practice should now be inactive
    const practiceMembers = membershipStore.filter(
      (m) => m.practiceId === practiceId,
    );
    for (const m of practiceMembers) {
      expect(m.isActive).toBe(false);
    }
  });

  // -------------------------------------------------------------------------
  // updateBillingMode
  // -------------------------------------------------------------------------

  it('updateBillingMode changes from INDIVIDUAL_EARLY_BIRD to PRACTICE_CONSOLIDATED', async () => {
    const data = makeMembershipData({ billingMode: 'INDIVIDUAL_EARLY_BIRD' });
    const created = await repo.createMembership(data as any);

    await repo.updateBillingMode(created.membershipId, 'PRACTICE_CONSOLIDATED');

    const stored = membershipStore.find(
      (m) => m.membershipId === created.membershipId,
    );
    expect(stored!.billingMode).toBe('PRACTICE_CONSOLIDATED');
  });

  // -------------------------------------------------------------------------
  // findMembershipsByBillingMode
  // -------------------------------------------------------------------------

  it('findMembershipsByBillingMode returns correct filtered results', async () => {
    const practiceId = crypto.randomUUID();
    await repo.createMembership(
      makeMembershipData({
        practiceId,
        physicianUserId: crypto.randomUUID(),
        billingMode: 'PRACTICE_CONSOLIDATED',
      }) as any,
    );
    await repo.createMembership(
      makeMembershipData({
        practiceId,
        physicianUserId: crypto.randomUUID(),
        billingMode: 'PRACTICE_CONSOLIDATED',
      }) as any,
    );
    await repo.createMembership(
      makeMembershipData({
        practiceId,
        physicianUserId: crypto.randomUUID(),
        billingMode: 'INDIVIDUAL_EARLY_BIRD',
      }) as any,
    );

    const consolidated = await repo.findMembershipsByBillingMode(
      practiceId,
      'PRACTICE_CONSOLIDATED',
    );
    expect(consolidated).toHaveLength(2);
    for (const m of consolidated) {
      expect(m.billingMode).toBe('PRACTICE_CONSOLIDATED');
    }

    const earlyBird = await repo.findMembershipsByBillingMode(
      practiceId,
      'INDIVIDUAL_EARLY_BIRD',
    );
    expect(earlyBird).toHaveLength(1);
    expect(earlyBird[0].billingMode).toBe('INDIVIDUAL_EARLY_BIRD');
  });

  // -------------------------------------------------------------------------
  // countActiveMembersByBillingMode
  // -------------------------------------------------------------------------

  it('countActiveMembersByBillingMode returns correct count', async () => {
    const practiceId = crypto.randomUUID();
    await repo.createMembership(
      makeMembershipData({
        practiceId,
        physicianUserId: crypto.randomUUID(),
        billingMode: 'PRACTICE_CONSOLIDATED',
      }) as any,
    );
    await repo.createMembership(
      makeMembershipData({
        practiceId,
        physicianUserId: crypto.randomUUID(),
        billingMode: 'PRACTICE_CONSOLIDATED',
      }) as any,
    );
    await repo.createMembership(
      makeMembershipData({
        practiceId,
        physicianUserId: crypto.randomUUID(),
        billingMode: 'INDIVIDUAL_EARLY_BIRD',
      }) as any,
    );

    const consolidatedCount = await repo.countActiveMembersByBillingMode(
      practiceId,
      'PRACTICE_CONSOLIDATED',
    );
    expect(consolidatedCount).toBe(2);

    const earlyBirdCount = await repo.countActiveMembersByBillingMode(
      practiceId,
      'INDIVIDUAL_EARLY_BIRD',
    );
    expect(earlyBirdCount).toBe(1);
  });

  // -------------------------------------------------------------------------
  // Unique index enforcement
  // -------------------------------------------------------------------------

  it('unique index prevents duplicate active membership for same physician', async () => {
    const physicianUserId = crypto.randomUUID();
    const data1 = makeMembershipData({
      physicianUserId,
      practiceId: crypto.randomUUID(),
    });
    await repo.createMembership(data1 as any);

    const data2 = makeMembershipData({
      physicianUserId,
      practiceId: crypto.randomUUID(),
    });

    await expect(repo.createMembership(data2 as any)).rejects.toThrow(
      /unique constraint/i,
    );
  });
});
