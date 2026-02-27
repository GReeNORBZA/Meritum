/**
 * Vitest Global Setup — DB lifecycle
 *
 * Since vitest's globalSetup runs in a separate process from test workers,
 * the actual DB initialisation is handled by setupTestDb() calls in each
 * test file's beforeAll (idempotent — only creates the DB once).
 *
 * This file exists to provide a hook point for future global setup needs.
 */

export async function setup() {
  // DB setup is handled by the idempotent setupTestDb() in test files.
  // The module-level singleton in db.ts ensures only one DB is created
  // per vitest worker process.
}

export async function teardown() {
  // Teardown is handled by the last test file's afterAll.
  // The test DB is disposable — if not cleaned up, it gets dropped
  // on the next run's setupTestDb() or manually.
}
