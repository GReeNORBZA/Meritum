import Fastify from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';

export function buildApp(opts = {}) {
  const app = Fastify({
    logger: {
      level: process.env.LOG_LEVEL ?? 'info',
    },
    genReqId: () => crypto.randomUUID(),
    ...opts,
  });

  // Register plugins
  app.register(helmet);
  app.register(cors, {
    origin: process.env.CORS_ORIGIN ?? 'http://localhost:3000',
  });
  app.register(rateLimit, {
    max: 100,
    timeWindow: '1 minute',
  });

  // Health check
  app.get('/health', async () => ({ status: 'ok' }));

  return app;
}

// Start server when run directly
if (require.main === module) {
  const app = buildApp();
  const port = parseInt(process.env.API_PORT ?? '3001', 10);
  const host = process.env.API_HOST ?? '0.0.0.0';

  app.listen({ port, host }, (err) => {
    if (err) {
      app.log.error(err);
      process.exit(1);
    }
  });
}
