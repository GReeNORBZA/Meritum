/**
 * Database Test Manager
 *
 * Provides a real PostgreSQL connection for DB integration tests.
 * Creates a disposable test database per test run, runs Drizzle migrations,
 * and exports helpers for obtaining the test db/pool.
 *
 * `setupTestDb()` is idempotent — safe to call from multiple test files.
 * `teardownTestDb()` drops the DB and closes the pool.
 */
import pg from 'pg';
import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import path from 'node:path';
import crypto from 'node:crypto';

const BASE_URL =
  process.env.DATABASE_URL ?? 'postgresql://meritum:meritum@localhost:5432/postgres';

const MIGRATIONS_FOLDER = path.resolve(__dirname, '../../drizzle/migrations');

let testDbName: string | undefined;
let testPool: pg.Pool | undefined;
let testDb: NodePgDatabase | undefined;
let setupPromise: Promise<void> | undefined;

/**
 * Create a disposable test database, run migrations, and initialise
 * the shared pool/drizzle instances used by all DB tests in the run.
 *
 * Idempotent — if already initialised, returns immediately.
 */
export async function setupTestDb(): Promise<void> {
  // Return the in-flight promise if already setting up (or done)
  if (setupPromise) return setupPromise;

  setupPromise = (async () => {
    const suffix = crypto.randomBytes(4).toString('hex');
    testDbName = `meritum_test_${suffix}`;

    // Connect to base database to create the test DB
    const adminPool = new pg.Pool({ connectionString: BASE_URL });
    try {
      await adminPool.query(`CREATE DATABASE "${testDbName}"`);
    } finally {
      await adminPool.end();
    }

    // Build the connection string for the test DB
    const parsed = new URL(BASE_URL);
    parsed.pathname = `/${testDbName}`;
    const testUrl = parsed.toString();

    testPool = new pg.Pool({ connectionString: testUrl });
    testDb = drizzle(testPool);

    // Run all Drizzle migrations
    await migrate(testDb, { migrationsFolder: MIGRATIONS_FOLDER });
  })();

  return setupPromise;
}

/**
 * Drop the disposable test database and close the pool.
 * Safe to call multiple times — no-ops if already torn down.
 */
export async function teardownTestDb(): Promise<void> {
  if (testPool) {
    await testPool.end();
    testPool = undefined;
  }

  if (testDbName) {
    const dbName = testDbName;
    testDbName = undefined;
    testDb = undefined;
    setupPromise = undefined;

    const adminPool = new pg.Pool({ connectionString: BASE_URL });
    try {
      // Terminate any lingering connections
      await adminPool.query(`
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE datname = '${dbName}' AND pid <> pg_backend_pid()
      `);
      await adminPool.query(`DROP DATABASE IF EXISTS "${dbName}"`);
    } finally {
      await adminPool.end();
    }
  }
}

/**
 * Return the shared Drizzle instance pointing at the test database.
 */
export function getTestDb(): NodePgDatabase {
  if (!testDb) throw new Error('Test DB not initialised — call setupTestDb() first');
  return testDb;
}

/**
 * Return the underlying pg.Pool for the test database.
 */
export function getTestPool(): pg.Pool {
  if (!testPool) throw new Error('Test pool not initialised — call setupTestDb() first');
  return testPool;
}

/**
 * Return the test database name (useful for debugging).
 */
export function getTestDbName(): string {
  return testDbName ?? '';
}
