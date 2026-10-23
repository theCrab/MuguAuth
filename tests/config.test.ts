import assert from "node:assert/strict";
import { test } from "node:test";
import { loadConfig } from "../src/config/env.js";

const validEnvironment = {
  DATABASE_URL: "postgres://user:pass@localhost:5432/mugu_auth",
  REDIS_URL: "redis://localhost:6379",
  SENDGRID_API_KEY: "test-sendgrid-key",
  SENDGRID_FROM_EMAIL: "auth@example.com",
  TWILIO_ACCOUNT_SID: `AC${"a".repeat(32)}`,
  TWILIO_AUTH_TOKEN: "test-twilio-token",
  TWILIO_FROM_NUMBER: "+15555550100",
  OTP_HMAC_SECRET: "test-otp-hmac-secret-with-at-least-32-characters",
  JWT_KEYS_DIR: "./secrets/jwt",
  JWT_ACTIVE_KID: "test-key-1",
  JWT_ISSUER: "https://auth.example.com",
  JWT_AUDIENCE: "mugu-auth-clients",
};

test("configuration rejects missing required values with field names", () => {
  assert.throws(
    () => loadConfig({}),
    (error: Error) => error.message.includes("DATABASE_URL")
      && error.message.includes("TWILIO_ACCOUNT_SID")
      && error.message.startsWith("Invalid environment configuration:"),
  );
});

test("configuration rejects invalid URLs and formats", () => {
  assert.throws(
    () => loadConfig({
      ...validEnvironment,
      DATABASE_URL: "http://localhost",
      TWILIO_FROM_NUMBER: "not-a-number",
    }),
    (error: Error) => error.message.includes("DATABASE_URL")
      && error.message.includes("TWILIO_FROM_NUMBER"),
  );
});

test("configuration applies a validated default port", () => {
  assert.equal(loadConfig(validEnvironment).PORT, 3000);
});
