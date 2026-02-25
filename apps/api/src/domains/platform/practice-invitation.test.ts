import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createPracticeInvitationRepository } from './practice-invitation.repository.js';

// ---------------------------------------------------------------------------
// In-memory store
// ---------------------------------------------------------------------------

let invitationStore: Record<string, any>[];

// ---------------------------------------------------------------------------
// Mock Drizzle DB
// ---------------------------------------------------------------------------

function makeMockDb() {
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

  function insertRow(values: any): any {
    const newInvitation = {
      invitationId: values.invitationId ?? crypto.randomUUID(),
      practiceId: values.practiceId,
      invitedEmail: values.invitedEmail,
      invitedByUserId: values.invitedByUserId,
      status: values.status ?? 'PENDING',
      tokenHash: values.tokenHash,
      expiresAt: values.expiresAt,
      createdAt: values.createdAt ?? new Date(),
    };
    invitationStore.push(newInvitation);
    return newInvitation;
  }

  function executeOp(ctx: any): any[] {
    switch (ctx.op) {
      case 'select': {
        let matches = invitationStore.filter((row) =>
          ctx.whereClauses.every((pred: any) => pred(row)),
        );
        return ctx.limitN ? matches.slice(0, ctx.limitN) : matches;
      }
      case 'insert': {
        const values = ctx.values;
        if (Array.isArray(values)) {
          return values.map((v: any) => insertRow(v));
        }
        return [insertRow(values)];
      }
      case 'update': {
        const updated: any[] = [];
        const matches = invitationStore.filter((row) =>
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
    sql: {},
  };
});

// Mock the schema module
vi.mock('@meritum/shared/schemas/db/platform.schema.js', () => {
  const makeCol = (name: string) => ({ name });

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
    practiceInvitations: practiceInvitationsProxy,
  };
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DAY_MS = 24 * 60 * 60 * 1000;

function makeInvitationData(overrides: Partial<Record<string, any>> = {}) {
  return {
    practiceId: overrides.practiceId ?? crypto.randomUUID(),
    invitedEmail: overrides.invitedEmail ?? 'doctor@example.com',
    invitedByUserId: overrides.invitedByUserId ?? crypto.randomUUID(),
    status: overrides.status ?? 'PENDING',
    tokenHash: overrides.tokenHash ?? crypto.randomUUID().replace(/-/g, ''),
    expiresAt: overrides.expiresAt ?? new Date(Date.now() + 7 * DAY_MS),
    createdAt: overrides.createdAt ?? new Date(),
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('PracticeInvitationRepository', () => {
  let repo: ReturnType<typeof createPracticeInvitationRepository>;
  let db: any;

  beforeEach(() => {
    invitationStore = [];
    db = makeMockDb();
    repo = createPracticeInvitationRepository(db);
  });

  // -------------------------------------------------------------------------
  // createInvitation
  // -------------------------------------------------------------------------

  it('createInvitation inserts and returns an invitation record', async () => {
    const data = makeInvitationData();
    const result = await repo.createInvitation(data as any);

    expect(result).toBeDefined();
    expect(result.invitationId).toBeDefined();
    expect(result.practiceId).toBe(data.practiceId);
    expect(result.invitedEmail).toBe(data.invitedEmail);
    expect(result.tokenHash).toBe(data.tokenHash);
    expect(invitationStore).toHaveLength(1);
  });

  it('createInvitation defaults status to PENDING', async () => {
    const data = makeInvitationData();
    delete (data as any).status;
    const result = await repo.createInvitation(data as any);

    expect(result.status).toBe('PENDING');
  });

  // -------------------------------------------------------------------------
  // findInvitationByTokenHash
  // -------------------------------------------------------------------------

  it('findInvitationByTokenHash returns matching invitation', async () => {
    const tokenHash = 'abc123hashvalue';
    const data = makeInvitationData({ tokenHash });
    await repo.createInvitation(data as any);

    const found = await repo.findInvitationByTokenHash(tokenHash);
    expect(found).toBeDefined();
    expect(found!.tokenHash).toBe(tokenHash);
  });

  it('findInvitationByTokenHash returns null for non-existent hash', async () => {
    const found = await repo.findInvitationByTokenHash('nonexistent');
    expect(found).toBeNull();
  });

  // -------------------------------------------------------------------------
  // findPendingInvitationByEmail
  // -------------------------------------------------------------------------

  it('findPendingInvitationByEmail returns pending invitation for email+practice', async () => {
    const practiceId = crypto.randomUUID();
    const email = 'doctor@example.com';
    const data = makeInvitationData({ practiceId, invitedEmail: email });
    await repo.createInvitation(data as any);

    const found = await repo.findPendingInvitationByEmail(email, practiceId);
    expect(found).toBeDefined();
    expect(found!.invitedEmail).toBe(email);
    expect(found!.practiceId).toBe(practiceId);
    expect(found!.status).toBe('PENDING');
  });

  it('findPendingInvitationByEmail returns null for accepted invitation', async () => {
    const practiceId = crypto.randomUUID();
    const email = 'doctor@example.com';
    // Insert directly with ACCEPTED status
    invitationStore.push({
      invitationId: crypto.randomUUID(),
      practiceId,
      invitedEmail: email,
      invitedByUserId: crypto.randomUUID(),
      status: 'ACCEPTED',
      tokenHash: 'hash123',
      expiresAt: new Date(Date.now() + 7 * DAY_MS),
      createdAt: new Date(),
    });

    const found = await repo.findPendingInvitationByEmail(email, practiceId);
    expect(found).toBeNull();
  });

  // -------------------------------------------------------------------------
  // findPendingInvitationsByPracticeId
  // -------------------------------------------------------------------------

  it('findPendingInvitationsByPracticeId returns all pending invitations', async () => {
    const practiceId = crypto.randomUUID();
    await repo.createInvitation(
      makeInvitationData({ practiceId, invitedEmail: 'a@example.com' }) as any,
    );
    await repo.createInvitation(
      makeInvitationData({ practiceId, invitedEmail: 'b@example.com' }) as any,
    );
    await repo.createInvitation(
      makeInvitationData({ practiceId, invitedEmail: 'c@example.com' }) as any,
    );

    const pending = await repo.findPendingInvitationsByPracticeId(practiceId);
    expect(pending).toHaveLength(3);
    for (const inv of pending) {
      expect(inv.practiceId).toBe(practiceId);
      expect(inv.status).toBe('PENDING');
    }
  });

  it('findPendingInvitationsByPracticeId excludes non-pending invitations', async () => {
    const practiceId = crypto.randomUUID();
    await repo.createInvitation(
      makeInvitationData({ practiceId, invitedEmail: 'pending@example.com' }) as any,
    );
    // Insert non-pending invitations directly
    invitationStore.push({
      invitationId: crypto.randomUUID(),
      practiceId,
      invitedEmail: 'accepted@example.com',
      invitedByUserId: crypto.randomUUID(),
      status: 'ACCEPTED',
      tokenHash: 'hash_accepted',
      expiresAt: new Date(Date.now() + 7 * DAY_MS),
      createdAt: new Date(),
    });
    invitationStore.push({
      invitationId: crypto.randomUUID(),
      practiceId,
      invitedEmail: 'declined@example.com',
      invitedByUserId: crypto.randomUUID(),
      status: 'DECLINED',
      tokenHash: 'hash_declined',
      expiresAt: new Date(Date.now() + 7 * DAY_MS),
      createdAt: new Date(),
    });
    invitationStore.push({
      invitationId: crypto.randomUUID(),
      practiceId,
      invitedEmail: 'expired@example.com',
      invitedByUserId: crypto.randomUUID(),
      status: 'EXPIRED',
      tokenHash: 'hash_expired',
      expiresAt: new Date(Date.now() - 1 * DAY_MS),
      createdAt: new Date(),
    });

    const pending = await repo.findPendingInvitationsByPracticeId(practiceId);
    expect(pending).toHaveLength(1);
    expect(pending[0].invitedEmail).toBe('pending@example.com');
  });

  // -------------------------------------------------------------------------
  // updateInvitationStatus
  // -------------------------------------------------------------------------

  it('updateInvitationStatus changes status to ACCEPTED', async () => {
    const data = makeInvitationData();
    const created = await repo.createInvitation(data as any);

    await repo.updateInvitationStatus(created.invitationId, 'ACCEPTED');

    const stored = invitationStore.find(
      (inv) => inv.invitationId === created.invitationId,
    );
    expect(stored!.status).toBe('ACCEPTED');
  });

  it('updateInvitationStatus changes status to DECLINED', async () => {
    const data = makeInvitationData();
    const created = await repo.createInvitation(data as any);

    await repo.updateInvitationStatus(created.invitationId, 'DECLINED');

    const stored = invitationStore.find(
      (inv) => inv.invitationId === created.invitationId,
    );
    expect(stored!.status).toBe('DECLINED');
  });

  it('updateInvitationStatus changes status to EXPIRED', async () => {
    const data = makeInvitationData();
    const created = await repo.createInvitation(data as any);

    await repo.updateInvitationStatus(created.invitationId, 'EXPIRED');

    const stored = invitationStore.find(
      (inv) => inv.invitationId === created.invitationId,
    );
    expect(stored!.status).toBe('EXPIRED');
  });

  // -------------------------------------------------------------------------
  // expireInvitations
  // -------------------------------------------------------------------------

  it('expireInvitations expires past-due pending invitations', async () => {
    const practiceId = crypto.randomUUID();
    // Pending invitation that expired yesterday
    invitationStore.push({
      invitationId: crypto.randomUUID(),
      practiceId,
      invitedEmail: 'expired1@example.com',
      invitedByUserId: crypto.randomUUID(),
      status: 'PENDING',
      tokenHash: 'hash_exp1',
      expiresAt: new Date(Date.now() - 1 * DAY_MS),
      createdAt: new Date(),
    });
    // Pending invitation that expires tomorrow (should NOT be expired)
    invitationStore.push({
      invitationId: crypto.randomUUID(),
      practiceId,
      invitedEmail: 'future@example.com',
      invitedByUserId: crypto.randomUUID(),
      status: 'PENDING',
      tokenHash: 'hash_future',
      expiresAt: new Date(Date.now() + 1 * DAY_MS),
      createdAt: new Date(),
    });

    const cutoff = new Date();
    const count = await repo.expireInvitations(cutoff);

    expect(count).toBe(1);
    const expired = invitationStore.find(
      (inv) => inv.invitedEmail === 'expired1@example.com',
    );
    expect(expired!.status).toBe('EXPIRED');

    const stillPending = invitationStore.find(
      (inv) => inv.invitedEmail === 'future@example.com',
    );
    expect(stillPending!.status).toBe('PENDING');
  });

  it('expireInvitations returns count of expired invitations', async () => {
    const practiceId = crypto.randomUUID();
    const pastDate = new Date(Date.now() - 2 * DAY_MS);
    // Add 3 expired pending invitations
    for (let i = 0; i < 3; i++) {
      invitationStore.push({
        invitationId: crypto.randomUUID(),
        practiceId,
        invitedEmail: `expired${i}@example.com`,
        invitedByUserId: crypto.randomUUID(),
        status: 'PENDING',
        tokenHash: `hash_exp_${i}`,
        expiresAt: pastDate,
        createdAt: new Date(),
      });
    }

    const count = await repo.expireInvitations(new Date());
    expect(count).toBe(3);
  });

  it('expireInvitations does not affect non-pending invitations', async () => {
    const practiceId = crypto.randomUUID();
    const pastDate = new Date(Date.now() - 2 * DAY_MS);

    // Already ACCEPTED invitation with past expiry
    invitationStore.push({
      invitationId: crypto.randomUUID(),
      practiceId,
      invitedEmail: 'accepted@example.com',
      invitedByUserId: crypto.randomUUID(),
      status: 'ACCEPTED',
      tokenHash: 'hash_accepted',
      expiresAt: pastDate,
      createdAt: new Date(),
    });
    // Already DECLINED invitation with past expiry
    invitationStore.push({
      invitationId: crypto.randomUUID(),
      practiceId,
      invitedEmail: 'declined@example.com',
      invitedByUserId: crypto.randomUUID(),
      status: 'DECLINED',
      tokenHash: 'hash_declined',
      expiresAt: pastDate,
      createdAt: new Date(),
    });
    // Already EXPIRED invitation with past expiry
    invitationStore.push({
      invitationId: crypto.randomUUID(),
      practiceId,
      invitedEmail: 'expired@example.com',
      invitedByUserId: crypto.randomUUID(),
      status: 'EXPIRED',
      tokenHash: 'hash_expired',
      expiresAt: pastDate,
      createdAt: new Date(),
    });

    const count = await repo.expireInvitations(new Date());
    expect(count).toBe(0);

    // Verify statuses were NOT changed
    expect(invitationStore.find((inv) => inv.invitedEmail === 'accepted@example.com')!.status).toBe('ACCEPTED');
    expect(invitationStore.find((inv) => inv.invitedEmail === 'declined@example.com')!.status).toBe('DECLINED');
    expect(invitationStore.find((inv) => inv.invitedEmail === 'expired@example.com')!.status).toBe('EXPIRED');
  });

  // -------------------------------------------------------------------------
  // findInvitationsByEmail
  // -------------------------------------------------------------------------

  it('findInvitationsByEmail returns all invitations for an email', async () => {
    const email = 'doctor@clinic.ca';
    const practiceId1 = crypto.randomUUID();
    const practiceId2 = crypto.randomUUID();

    // PENDING invitation
    await repo.createInvitation(
      makeInvitationData({ invitedEmail: email, practiceId: practiceId1 }) as any,
    );
    // ACCEPTED invitation (insert directly)
    invitationStore.push({
      invitationId: crypto.randomUUID(),
      practiceId: practiceId2,
      invitedEmail: email,
      invitedByUserId: crypto.randomUUID(),
      status: 'ACCEPTED',
      tokenHash: 'hash_accepted',
      expiresAt: new Date(Date.now() + 7 * DAY_MS),
      createdAt: new Date(),
    });
    // Different email — should not appear
    await repo.createInvitation(
      makeInvitationData({ invitedEmail: 'other@clinic.ca', practiceId: practiceId1 }) as any,
    );

    const results = await repo.findInvitationsByEmail(email);
    expect(results).toHaveLength(2);
    for (const inv of results) {
      expect(inv.invitedEmail).toBe(email);
    }
  });
});
