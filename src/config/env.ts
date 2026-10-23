import { z } from "zod";

const environmentSchema = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  DATABASE_URL: z.url().refine((value) => value.startsWith("postgres")),
  REDIS_URL: z.url().refine((value) => value.startsWith("redis")),
  SENDGRID_API_KEY: z.string().min(1),
  SENDGRID_FROM_EMAIL: z.email(),
  TWILIO_ACCOUNT_SID: z.string().regex(/^AC[0-9a-fA-F]{32}$/),
  TWILIO_AUTH_TOKEN: z.string().min(1),
  TWILIO_FROM_NUMBER: z.string().regex(/^\+[1-9]\d{1,14}$/),
  OTP_HMAC_SECRET: z.string().min(32),
  JWT_KEYS_DIR: z.string().min(1),
  JWT_ACTIVE_KID: z.string().regex(/^[A-Za-z0-9._-]{1,128}$/),
  JWT_ISSUER: z.url(),
  JWT_AUDIENCE: z.string().min(1),
});

export type AppConfig = z.infer<typeof environmentSchema>;

export function loadConfig(environment: NodeJS.ProcessEnv = process.env): AppConfig {
  const result = environmentSchema.safeParse(environment);
  if (!result.success) {
    const details = result.error.issues
      .map((issue) => `${issue.path.join(".") || "environment"}: ${issue.message}`)
      .join("; ");
    throw new Error(`Invalid environment configuration: ${details}`);
  }

  return result.data;
}
