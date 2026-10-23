import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { importJWK, jwtVerify, type JWK } from "jose";
import { Redis } from "ioredis";
import { RedisMemoryServer } from "redis-memory-server";
import { Client, Pool } from "pg";
import type { AppConfig } from "../src/config/env.js";
import { createApp } from "../src/app.js";
import { UserModel } from "../src/models/user.model.js";
import { migrateUp } from "../src/db/migrations.js";
import { createAuthMiddleware } from "../src/middlewares/auth.middleware.js";
import { createAuthRouter } from "../src/routes/auth.routes.js";
import { createJwksRouter } from "../src/routes/jwks.routes.js";
import { createProtectedRouter } from "../src/routes/protected.routes.js";
import { AuthTokenService } from "../src/services/auth-token.service.js";
import { JwksService } from "../src/services/jwks.service.js";
import { OtpService } from "../src/services/otp.service.js";
import { RefreshService } from "../src/services/refresh.service.js";
import { RefreshTokenStore } from "../src/services/refresh-token.store.js";
import { RegistrationStore } from "../src/services/registration.store.js";
import { SignupService } from "../src/services/signup.service.js";
import type { Server } from "node:http";

const testDatabaseUrl = process.env.TEST_DATABASE_URL;

test("passwordless signup completes both orders and protects suspended accounts", {
  skip: !testDatabaseUrl,
}, async () => {
  if (!testDatabaseUrl) throw new Error("TEST_DATABASE_URL must be set for end-to-end tests");

  const schema = `signup_e2e_${randomUUID().replaceAll("-", "")}`;
  const keyDirectory = await mkdtemp(join(tmpdir(), "muguauth-e2e-"));
  const setupClient = new Client({ connectionString: testDatabaseUrl });
  let redisServer: RedisMemoryServer | undefined;
  let redis: Redis | undefined;
  let pool: Pool | undefined;
  let server: Server | undefined;

  await setupClient.connect();
  try {
    await setupClient.query(`CREATE SCHEMA "${schema}"`);
    await setupClient.query(`SET search_path TO "${schema}"`);
    await migrateUp(setupClient);

    const database = new Pool({
      connectionString: testDatabaseUrl,
      options: `-c search_path=${schema}`,
    });
    pool = database;
    redisServer = await RedisMemoryServer.create({
      autoStart: true,
      binary: { version: "7.4.2" },
    });
    redis = new Redis(
      `redis://${await redisServer.getHost()}:${await redisServer.getPort()}`,
      { lazyConnect: true, maxRetriesPerRequest: 1 },
    );
    await redis.connect();

    const kid = "e2e-key";
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256",
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    await writeFile(join(keyDirectory, `${kid}.pem`), privateKey);
    await writeFile(join(keyDirectory, `${kid}.public.pem`), publicKey);

    const config: Pick<
      AppConfig,
      "JWT_KEYS_DIR" | "JWT_ACTIVE_KID" | "JWT_ISSUER" | "JWT_AUDIENCE"
    > = {
      JWT_KEYS_DIR: keyDirectory,
      JWT_ACTIVE_KID: kid,
      JWT_ISSUER: "https://auth.example.com",
      JWT_AUDIENCE: "mugu-auth-clients",
    };
    const users = new UserModel(database);
    const registrations = new RegistrationStore(redis);
    const emailCodes = new Map<string, string>();
    const phoneCodes = new Map<string, string>();
    const tokens = new AuthTokenService(new RefreshTokenStore(redis), config);
    const jwks = new JwksService(config);
    const signup = new SignupService(
      registrations,
      new OtpService(
        registrations,
        "test-otp-hmac-secret-with-at-least-32-characters",
      ),
      {
        sendVerificationCode: async (email, code) => {
          emailCodes.set(email, code);
        },
      },
      {
        sendVerificationCode: async (phone, code) => {
          phoneCodes.set(phone, code);
        },
      },
      users,
      tokens,
    );
    const refresh = new RefreshService(new RefreshTokenStore(redis), tokens, users);
    const app = createApp(
      createAuthRouter(signup, refresh),
      createJwksRouter(jwks),
      createProtectedRouter(createAuthMiddleware(users, jwks, config)),
    );
    server = app.listen(0);
    await once(server, "listening");
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const baseUrl = `http://127.0.0.1:${address.port}`;

    const countUsers = async (): Promise<number> => {
      const result = await database.query<{ count: string }>("SELECT count(*) FROM users");
      return Number(result.rows[0]?.count);
    };

    const completeSignup = async (
      email: string,
      phoneNumber: string,
      order: readonly ("email" | "phone")[],
    ) => {
      const usersBeforeSignup = await countUsers();
      const started = await fetch(`${baseUrl}/auth/signup`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, phoneNumber }),
      });
      assert.equal(started.status, 201);
      const startBody = await started.json() as {
        data: { registrationId: string };
      };
      assert.equal(await countUsers(), usersBeforeSignup);

      let tokens: {
        accessToken: string;
        accessTokenExpiresIn: number;
        refreshToken: string;
        refreshTokenExpiresAt: string;
      } | undefined;
      for (const [index, channel] of order.entries()) {
        const code = channel === "email" ? emailCodes.get(email) : phoneCodes.get(phoneNumber);
        assert.ok(code);
        const response = await fetch(
          `${baseUrl}/auth/signup/${startBody.data.registrationId}/verify/${channel}`,
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ code }),
          },
        );
        assert.equal(response.status, 200);
        const body = await response.json() as {
          data: {
            registrationComplete: boolean;
            tokens?: typeof tokens;
          };
        };
        assert.equal(body.data.registrationComplete, index === order.length - 1);
        if (index === order.length - 1) {
          tokens = body.data.tokens;
          assert.ok(tokens);
          assert.equal(tokens.accessTokenExpiresIn, 900);
          assert.equal(await countUsers(), usersBeforeSignup + 1);
        } else {
          assert.equal(body.data.tokens, undefined);
          assert.equal(await countUsers(), usersBeforeSignup);
        }
      }

      assert.ok(tokens);
      return tokens;
    };

    const emailFirstTokens = await completeSignup(
      "email-first@example.com",
      "+14155552671",
      ["email", "phone"],
    );
    const phoneFirstTokens = await completeSignup(
      "phone-first@example.com",
      "+14155552672",
      ["phone", "email"],
    );
    assert.equal(await countUsers(), 2);

    const pendingResponse = await fetch(`${baseUrl}/auth/signup`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        email: "expires@example.com",
        phoneNumber: "+14155552673",
      }),
    });
    assert.equal(pendingResponse.status, 201);
    const pendingBody = await pendingResponse.json() as {
      data: { registrationId: string };
    };
    await redis.pexpire(
      `signup:registration:${pendingBody.data.registrationId}`,
      1,
    );
    await new Promise((resolve) => setTimeout(resolve, 1_100));
    const expiredVerification = await fetch(
      `${baseUrl}/auth/signup/${pendingBody.data.registrationId}/verify/email`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code: emailCodes.get("expires@example.com") }),
      },
    );
    assert.equal(expiredVerification.status, 410);
    assert.equal(await countUsers(), 2);

    const jwksResponse = await fetch(`${baseUrl}/.well-known/jwks.json`);
    assert.equal(jwksResponse.status, 200);
    const jwksDocument = await jwksResponse.json() as { keys: JWK[] };
    const accessKey = jwksDocument.keys.find((key) => key.kid === kid);
    assert.ok(accessKey);
    const verified = await jwtVerify(
      emailFirstTokens.accessToken,
      await importJWK(accessKey, "ES256"),
      {
        algorithms: ["ES256"],
        issuer: config.JWT_ISSUER,
        audience: config.JWT_AUDIENCE,
      },
    );
    const verifiedPhoneToken = await jwtVerify(
      phoneFirstTokens.accessToken,
      await importJWK(accessKey, "ES256"),
      {
        algorithms: ["ES256"],
        issuer: config.JWT_ISSUER,
        audience: config.JWT_AUDIENCE,
      },
    );
    assert.notEqual(verified.payload.sub, verifiedPhoneToken.payload.sub);

    const activeResponse = await fetch(`${baseUrl}/auth/me`, {
      headers: { authorization: `Bearer ${emailFirstTokens.accessToken}` },
    });
    assert.equal(activeResponse.status, 200);
    const userId = verified.payload.sub;
    assert.equal(typeof userId, "string");
    await database.query("UPDATE users SET is_active = false WHERE id = $1", [userId]);
    const suspendedResponse = await fetch(`${baseUrl}/auth/me`, {
      headers: { authorization: `Bearer ${emailFirstTokens.accessToken}` },
    });
    assert.equal(suspendedResponse.status, 403);
  } finally {
    if (server?.listening) {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    }
    await pool?.end();
    await redis?.quit();
    await redisServer?.stop();
    await setupClient.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    await setupClient.end();
    await rm(keyDirectory, { recursive: true, force: true });
  }
});
