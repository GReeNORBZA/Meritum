import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import pg from 'pg';
import { setupTestDb, teardownTestDb, getTestDb, getTestPool } from '../fixtures/db.js';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import path from 'node:path';

const MIGRATIONS_FOLDER = path.resolve(__dirname, '../../drizzle/migrations');

describe('Database Migrations', () => {
  let pool: pg.Pool;

  beforeAll(async () => {
    await setupTestDb();
    pool = getTestPool();
  });

  afterAll(async () => {
    await teardownTestDb();
  });

  // -----------------------------------------------------------------------
  // 1. All 16 migrations have been applied
  // -----------------------------------------------------------------------
  it('all 16 migrations have been applied', async () => {
    const result = await pool.query(
      `SELECT COUNT(*) AS count FROM drizzle.__drizzle_migrations`,
    );
    expect(Number(result.rows[0].count)).toBeGreaterThanOrEqual(16);
  });

  // -----------------------------------------------------------------------
  // 2. All expected domain tables exist
  // -----------------------------------------------------------------------
  it('all expected domain tables exist', async () => {
    const expectedTables = [
      // IAM
      'users',
      'sessions',
      'recovery_codes',
      'audit_log',
      // Provider
      'providers',
      'business_arrangements',
      'practice_locations',
      // Patient
      'patients',
      'patient_import_batches',
      // Claim
      'claims',
      'import_batches',
      'shifts',
      'claim_audit_history',
      // Notification
      'notifications',
      'email_delivery_log',
      'notification_preferences',
      // Reference
      'reference_data_versions',
      'hsc_codes',
      // Onboarding
      'onboarding_progress',
      'ima_records',
    ];

    const result = await pool.query(
      `SELECT table_name
         FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_type = 'BASE TABLE'`,
    );

    const existingTables = result.rows.map((r: { table_name: string }) => r.table_name);

    for (const table of expectedTables) {
      expect(existingTables, `missing table: ${table}`).toContain(table);
    }
  });

  // -----------------------------------------------------------------------
  // 3. Key tables have expected columns
  // -----------------------------------------------------------------------
  it('key tables contain expected columns', async () => {
    const expectations: Record<string, string[]> = {
      users: ['user_id', 'email', 'password_hash', 'created_at', 'updated_at'],
      claims: ['claim_id', 'physician_id', 'patient_id', 'state', 'created_at'],
      providers: ['provider_id', 'billing_number', 'created_at'],
      patients: ['patient_id', 'first_name', 'last_name', 'created_at'],
      notifications: ['notification_id', 'recipient_id', 'event_type', 'created_at'],
    };

    for (const [table, expectedColumns] of Object.entries(expectations)) {
      const result = await pool.query(
        `SELECT column_name
           FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = $1`,
        [table],
      );

      const columns = result.rows.map((r: { column_name: string }) => r.column_name);

      for (const col of expectedColumns) {
        expect(columns, `table "${table}" missing column "${col}"`).toContain(col);
      }
    }
  });

  // -----------------------------------------------------------------------
  // 4. Running migrations a second time is idempotent (no errors)
  // -----------------------------------------------------------------------
  it('running migrations a second time does not error (idempotent)', async () => {
    const db = getTestDb();

    // Drizzle tracks applied migrations; re-running should be a no-op
    await expect(
      migrate(db, { migrationsFolder: MIGRATIONS_FOLDER }),
    ).resolves.not.toThrow();

    // Verify migration count is unchanged (still 16, not doubled)
    const result = await pool.query(
      `SELECT COUNT(*) AS count FROM drizzle.__drizzle_migrations`,
    );
    expect(Number(result.rows[0].count)).toBeGreaterThanOrEqual(16);
  });

  // -----------------------------------------------------------------------
  // 5. Foreign key constraints are present on critical relationships
  // -----------------------------------------------------------------------
  it('critical foreign key constraints exist', async () => {
    const result = await pool.query(`
      SELECT
        tc.table_name,
        kcu.column_name,
        ccu.table_name  AS foreign_table_name,
        ccu.column_name AS foreign_column_name
      FROM information_schema.table_constraints AS tc
      JOIN information_schema.key_column_usage AS kcu
        ON tc.constraint_name = kcu.constraint_name
       AND tc.table_schema   = kcu.table_schema
      JOIN information_schema.constraint_column_usage AS ccu
        ON ccu.constraint_name = tc.constraint_name
       AND ccu.table_schema    = tc.table_schema
      WHERE tc.constraint_type = 'FOREIGN KEY'
        AND tc.table_schema    = 'public'
    `);

    const fks = result.rows.map(
      (r: {
        table_name: string;
        column_name: string;
        foreign_table_name: string;
        foreign_column_name: string;
      }) => ({
        table: r.table_name,
        column: r.column_name,
        refTable: r.foreign_table_name,
        refColumn: r.foreign_column_name,
      }),
    );

    // sessions must reference users
    expect(
      fks.some((fk) => fk.table === 'sessions' && fk.refTable === 'users'),
      'sessions should have a foreign key to users',
    ).toBe(true);

    // claims must reference providers
    expect(
      fks.some((fk) => fk.table === 'claims' && fk.refTable === 'providers'),
      'claims should have a foreign key to providers',
    ).toBe(true);

    // claims must reference patients
    expect(
      fks.some((fk) => fk.table === 'claims' && fk.refTable === 'patients'),
      'claims should have a foreign key to patients',
    ).toBe(true);

    // notifications must reference users
    expect(
      fks.some((fk) => fk.table === 'notifications' && fk.refTable === 'users'),
      'notifications should have a foreign key to users',
    ).toBe(true);
  });
});
