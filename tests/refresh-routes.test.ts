import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { Redis } from "ioredis";
import { RedisMemoryServer } from "redis-memory-server";
import type { AppConfig } from "../src/config/env.js";
import { createApp } from "../src/app.js";
import { createAuthRouter } from "../src/routes/auth.routes.js";
import { AuthTokenService } from "../src/services/auth-token.service.js";
import { OtpService } from "../src/services/otp.service.js";
import { RefreshService } from "../src/services/refresh.service.js";
import { RefreshTokenStore } from "../src/services/refresh-token.store.js";
import { RegistrationStore } from "../src/services/registration.store.js";
import { SignupService } from "../src/services/signup.service.js";

let redisServer: RedisMemoryServer | undefined;
let redisUrl: string;

before(async () => {
  redisServer = await RedisMemoryServer.create({
    autoStart: true,
    binary: { version: "7.4.2" },
  });
  redisUrl = `redis://${await redisServer.getHost()}:${await redisServer.getPort()}`;
});

after(async () => {
  await redisServer?.stop();
});

test("refresh endpoint rotates once, revokes on reuse, and refuses inactive accounts", async () => {
  if (!redisUrl) throw new Error("Redis integration test server failed to start");
  const redis = new Redis(redisUrl, { lazyConnect: true, maxRetriesPerRequest: 1 });
  const keyDirectory = await mkdtemp(join(tmpdir(), "muguauth-refresh-"));
  await redis.connect();

  let server: ReturnType<ReturnType<typeof createApp>["listen"]> | undefined;
  try {
    const kid = "refresh-test-key";
    const { privateKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256",
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    await writeFile(join(keyDirectory, `${kid}.pem`), privateKey);

    const tokenConfig: Pick<
      AppConfig,
      "JWT_KEYS_DIR" | "JWT_ACTIVE_KID" | "JWT_ISSUER" | "JWT_AUDIENCE"
    > = {
      JWT_KEYS_DIR: keyDirectory,
      JWT_ACTIVE_KID: kid,
      JWT_ISSUER: "https://auth.example.com",
      JWT_AUDIENCE: "mugu-auth-clients",
    };
    const refreshTokens = new RefreshTokenStore(redis);
    const tokenService = new AuthTokenService(refreshTokens, tokenConfig);
    let userActive = true;
    const users = {
      findById: async (id: string) => ({
        id,
        email: "person@example.com",
        phone_number: "+14155552671",
        is_active: userActive,
        created_at: new Date(),
      }),
    };
    const registrations = new RegistrationStore(redis);
    const signup = new SignupService(
      registrations,
      new OtpService(
        registrations,
        "test-otp-hmac-secret-with-at-least-32-characters",
      ),
      { sendVerificationCode: async () => undefined },
      { sendVerificationCode: async () => undefined },
      {
        createOrGetByContacts: async () => {
          throw new Error("Signup is not used by this test");
        },
      },
      {
        issueForUser: async () => {
          throw new Error("Signup is not used by this test");
        },
      },
    );
    const app = createApp(createAuthRouter(
      signup,
      new RefreshService(refreshTokens, tokenService, users),
    ));
    server = app.listen(0);

    await once(server, "listening");
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const url = `http://127.0.0.1:${address.port}/auth/refresh`;

    const initial = await tokenService.issueForUser("user-123");
    const firstResponse = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ refreshToken: initial.refreshToken }),
    });
    assert.equal(firstResponse.status, 200);
    const firstBody = await firstResponse.json() as {
      success: boolean;
      data: { tokens: typeof initial };
    };
    assert.equal(firstBody.success, true);
    assert.notEqual(firstBody.data.tokens.refreshToken, initial.refreshToken);
    assert.equal(
      firstBody.data.tokens.refreshTokenExpiresAt,
      initial.refreshTokenExpiresAt,
    );
    assert.equal(firstBody.data.tokens.accessTokenExpiresIn, 900);

    const replayResponse = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ refreshToken: initial.refreshToken }),
    });
    assert.equal(replayResponse.status, 401);
    const successorResponse = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ refreshToken: firstBody.data.tokens.refreshToken }),
    });
    assert.equal(successorResponse.status, 401);

    const inactiveTokens = await tokenService.issueForUser("user-123");
    userActive = false;
    const inactiveResponse = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ refreshToken: inactiveTokens.refreshToken }),
    });
    assert.equal(inactiveResponse.status, 403);
    assert.equal(
      (await refreshTokens.inspect(inactiveTokens.refreshToken))?.status,
      "active",
    );

    userActive = true;
    const concurrentTokens = await tokenService.issueForUser("user-123");
    const concurrentResponses = await Promise.all(
      Array.from({ length: 2 }, () => fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ refreshToken: concurrentTokens.refreshToken }),
      })),
    );
    assert.deepEqual(
      concurrentResponses.map((response) => response.status).sort(),
      [200, 401],
    );
    const successful = concurrentResponses.find((response) => response.status === 200);
    assert.ok(successful);
    const successfulBody = await successful.json() as {
      data: { tokens: typeof initial };
    };
    const afterReplay = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        refreshToken: successfulBody.data.tokens.refreshToken,
      }),
    });
    assert.equal(afterReplay.status, 401);

    const expiredTokens = await tokenService.issueForUser("user-123");
    const expiredRecord = await refreshTokens.inspect(expiredTokens.refreshToken);
    assert.ok(expiredRecord);
    await redis.pexpireat(
      `auth:refresh:family:${expiredRecord.familyId}`,
      Date.now() - 1,
    );
    const expiredResponse = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ refreshToken: expiredTokens.refreshToken }),
    });
    assert.equal(expiredResponse.status, 401);
  } finally {
    if (server?.listening) {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    }
    await redis.quit();
    await rm(keyDirectory, { recursive: true, force: true });
  }
});
