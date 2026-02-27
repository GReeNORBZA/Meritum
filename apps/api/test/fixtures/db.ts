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
import dotenv from 'dotenv';

// Load .env so DATABASE_URL is available in test runs
dotenv.config({ path: path.resolve(__dirname, '../../../../.env') });

const BASE_URL =
  process.env.DATABASE_URL ?? 'postgresql://meritum:meritum@localhost:5432/meritum';

const MIGRATIONS_FOLDER = path.resolve(__dirname, '../../drizzle/migrations');

/**
 * Build a connection string that targets the `postgres` maintenance database
 * (needed for CREATE/DROP DATABASE) while preserving user/password/host/port.
 */
function adminConnectionString(): string {
  const parsed = new URL(BASE_URL);
  parsed.pathname = '/postgres';
  // Strip any query params like sslmode that may break admin ops
  parsed.search = '';
  return parsed.toString();
}

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

    // Connect to the `postgres` maintenance database to create the test DB
    const adminPool = new pg.Pool({ connectionString: adminConnectionString() });
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

    // Create required extensions before running migrations
    await testPool.query('CREATE EXTENSION IF NOT EXISTS "pg_trgm"');

    // Run all Drizzle migrations
    await migrate(testDb, { migrationsFolder: MIGRATIONS_FOLDER });

    // Patch schema-migration drift: add columns/tables that exist in the
    // Drizzle schema but haven't been captured in a migration file yet.
    await applySchemaPatches(testPool);
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

    const adminPool = new pg.Pool({ connectionString: adminConnectionString() });
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

// ---------------------------------------------------------------------------
// Schema patches — columns / tables in Drizzle schema but not yet migrated
// ---------------------------------------------------------------------------

async function applySchemaPatches(pool: pg.Pool): Promise<void> {
  // -- providers: missing columns --
  await pool.query(`
    ALTER TABLE providers
      ADD COLUMN IF NOT EXISTS is_connect_care_user boolean NOT NULL DEFAULT false,
      ADD COLUMN IF NOT EXISTS connect_care_enabled_at timestamptz
  `);

  // -- claims: missing columns --
  await pool.query(`
    ALTER TABLE claims
      ADD COLUMN IF NOT EXISTS raw_file_reference varchar(500),
      ADD COLUMN IF NOT EXISTS scc_charge_status varchar(20),
      ADD COLUMN IF NOT EXISTS icd_conversion_flag boolean DEFAULT false,
      ADD COLUMN IF NOT EXISTS icd10_source_code varchar(10),
      ADD COLUMN IF NOT EXISTS routing_ba_id uuid,
      ADD COLUMN IF NOT EXISTS routing_reason varchar(30)
  `);

  // -- import_batches: missing columns --
  await pool.query(`
    ALTER TABLE import_batches
      ADD COLUMN IF NOT EXISTS import_source varchar(30),
      ADD COLUMN IF NOT EXISTS scc_spec_version varchar(20),
      ADD COLUMN IF NOT EXISTS raw_row_count integer,
      ADD COLUMN IF NOT EXISTS valid_row_count integer,
      ADD COLUMN IF NOT EXISTS warning_count integer,
      ADD COLUMN IF NOT EXISTS duplicate_count integer,
      ADD COLUMN IF NOT EXISTS confirmation_status varchar(20),
      ADD COLUMN IF NOT EXISTS confirmed_at timestamptz,
      ADD COLUMN IF NOT EXISTS confirmed_by uuid REFERENCES users(user_id)
  `);

  // -- claim_templates: entire table missing --
  await pool.query(`
    CREATE TABLE IF NOT EXISTS claim_templates (
      template_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      physician_id uuid NOT NULL REFERENCES providers(provider_id),
      name varchar(100) NOT NULL,
      description text,
      template_type varchar(30) NOT NULL,
      claim_type varchar(10) NOT NULL,
      line_items jsonb NOT NULL,
      specialty_code varchar(10),
      usage_count integer NOT NULL DEFAULT 0,
      is_active boolean NOT NULL DEFAULT true,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    )
  `);

  // -- recent_referrers: entire table missing --
  await pool.query(`
    CREATE TABLE IF NOT EXISTS recent_referrers (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      physician_id uuid NOT NULL REFERENCES providers(provider_id),
      referrer_cpsa varchar(10) NOT NULL,
      referrer_name varchar(100) NOT NULL,
      use_count integer NOT NULL DEFAULT 1,
      last_used_at timestamptz NOT NULL DEFAULT now()
    )
  `);

  // -- claim_justifications: entire table missing --
  await pool.query(`
    CREATE TABLE IF NOT EXISTS claim_justifications (
      justification_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      claim_id uuid NOT NULL REFERENCES claims(claim_id),
      physician_id uuid NOT NULL REFERENCES providers(provider_id),
      scenario varchar(40) NOT NULL,
      justification_text text NOT NULL,
      template_id uuid,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      created_by uuid NOT NULL REFERENCES users(user_id)
    )
  `);

  // -- patient_eligibility_cache: entire table missing --
  await pool.query(`
    CREATE TABLE IF NOT EXISTS patient_eligibility_cache (
      cache_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      provider_id uuid NOT NULL REFERENCES providers(provider_id),
      phn_hash varchar(64) NOT NULL,
      is_eligible boolean NOT NULL,
      eligibility_details jsonb,
      verified_at timestamptz NOT NULL,
      expires_at timestamptz NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (provider_id, phn_hash)
    )
  `);
}
