/**
 * Test App Builder
 *
 * Builds a Fastify app with real DB-backed repositories for cross-domain
 * and WebSocket tests that need a full app stack.
 */
import Fastify, { type FastifyInstance } from 'fastify';
import { type NodePgDatabase } from 'drizzle-orm/node-postgres';

import { createClaimRepository } from '../../src/domains/claim/claim.repository.js';
import { createPatientRepository } from '../../src/domains/patient/patient.repository.js';
import { createUserRepository, createSessionRepository } from '../../src/domains/iam/iam.repository.js';
import { createNotificationRepository } from '../../src/domains/notification/notification.repository.js';
import { createReferenceRepository } from '../../src/domains/reference/reference.repository.js';
import { createOnboardingRepository } from '../../src/domains/onboarding/onboarding.repository.js';
import { createProviderRepository } from '../../src/domains/provider/provider.repository.js';

export interface TestAppContext {
  app: FastifyInstance;
  repos: {
    claim: ReturnType<typeof createClaimRepository>;
    patient: ReturnType<typeof createPatientRepository>;
    user: ReturnType<typeof createUserRepository>;
    session: ReturnType<typeof createSessionRepository>;
    notification: ReturnType<typeof createNotificationRepository>;
    reference: ReturnType<typeof createReferenceRepository>;
    onboarding: ReturnType<typeof createOnboardingRepository>;
    provider: ReturnType<typeof createProviderRepository>;
  };
}

/**
 * Build a Fastify app with real DB-backed repositories.
 * Disables logging in test mode for clean output.
 */
export async function buildTestApp(db: NodePgDatabase): Promise<TestAppContext> {
  const app = Fastify({
    logger: false,
    genReqId: () => crypto.randomUUID(),
  });

  const repos = {
    claim: createClaimRepository(db),
    patient: createPatientRepository(db),
    user: createUserRepository(db),
    session: createSessionRepository(db),
    notification: createNotificationRepository(db),
    reference: createReferenceRepository(db),
    onboarding: createOnboardingRepository(db),
    provider: createProviderRepository(db),
  };

  // Health check
  app.get('/health', async () => ({ status: 'ok' }));

  return { app, repos };
}
