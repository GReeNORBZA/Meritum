import dotenv from 'dotenv';
import path from 'path';
import { z } from 'zod';

// Load .env from monorepo root
dotenv.config({ path: path.resolve(__dirname, '../../../../.env') });

const envSchema = z.object({
  DATABASE_URL: z.string().min(1),
  DATABASE_URL_TEST: z.string().optional(),
  SESSION_SECRET: z.string().min(1),
  ARGON2_MEMORY: z.coerce.number().default(19456),
  ARGON2_ITERATIONS: z.coerce.number().default(2),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  API_PORT: z.coerce.number().default(3001),
  API_HOST: z.string().default('0.0.0.0'),
  CORS_ORIGIN: z.string().default('http://localhost:3000'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
});

export type Env = z.infer<typeof envSchema>;

let _env: Env | undefined;

export function getEnv(): Env {
  if (!_env) {
    const result = envSchema.safeParse(process.env);
    if (!result.success) {
      console.error('Invalid environment variables:', result.error.flatten().fieldErrors);
      throw new Error('Invalid environment variables');
    }
    _env = result.data;
  }
  return _env;
}
