/**
 * Test Helpers
 *
 * Transaction wrapper for test isolation, authenticated session helper,
 * and table truncation utility.
 */
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';
import { sql } from 'drizzle-orm';
import crypto from 'node:crypto';

import { users, sessions } from '@meritum/shared/schemas/db/iam.schema.js';

/**
 * Wrap a test body in a transaction that always rolls back.
 * Provides complete test isolation without recreating the DB per test.
 *
 * Usage:
 * ```ts
 * it('does something', () => withTestTransaction(db, async (tx) => {
 *   // use tx instead of db — all changes rolled back after test
 * }));
 * ```
 *
 * NOTE: Drizzle's `db.transaction()` executes inside a real PG transaction.
 * We force a rollback by throwing a sentinel error after the test body runs.
 */
const ROLLBACK_SENTINEL = '__TEST_ROLLBACK__';

export async function withTestTransaction<T>(
  db: NodePgDatabase,
  fn: (tx: NodePgDatabase) => Promise<T>,
): Promise<T> {
  let result: T | undefined;
  try {
    await (db as any).transaction(async (tx: NodePgDatabase) => {
      result = await fn(tx);
      throw new Error(ROLLBACK_SENTINEL);
    });
  } catch (err: any) {
    if (err?.message !== ROLLBACK_SENTINEL) throw err;
  }
  return result as T;
}

/**
 * Hash a raw session token with SHA-256 (matches the auth plugin).
 */
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Create a user + session in the real DB and return identifiers.
 * Useful for tests that need an authenticated context.
 */
export async function createAuthenticatedSession(
  db: NodePgDatabase,
  overrides: {
    email?: string;
    fullName?: string;
    role?: string;
    passwordHash?: string;
  } = {},
) {
  const email = overrides.email ?? `test-${crypto.randomUUID()}@meritum.test`;
  const fullName = overrides.fullName ?? 'Test User';
  const role = overrides.role ?? 'PHYSICIAN';
  const passwordHash =
    overrides.passwordHash ??
    '$argon2id$v=19$m=65536,t=3,p=4$salt$fakehashfortest';

  const [user] = await db
    .insert(users)
    .values({ email, passwordHash, fullName, role })
    .returning();

  const sessionToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashToken(sessionToken);

  const [session] = await db
    .insert(sessions)
    .values({
      userId: user.userId,
      tokenHash,
      ipAddress: '127.0.0.1',
      userAgent: 'vitest',
    })
    .returning();

  return {
    userId: user.userId,
    email,
    sessionToken,
    tokenHash,
    sessionId: session.sessionId,
  };
}

/**
 * Truncate a table (cascade). Use sparingly — prefer `withTestTransaction`.
 */
export async function cleanTable(
  db: NodePgDatabase,
  tableName: string,
): Promise<void> {
  await db.execute(sql.raw(`TRUNCATE TABLE "${tableName}" CASCADE`));
}
