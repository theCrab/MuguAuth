import assert from "node:assert/strict";
import { once } from "node:events";
import { after, before, test } from "node:test";
import { Redis } from "ioredis";
import { RedisMemoryServer } from "redis-memory-server";
import { createApp } from "../src/app.js";
import { createAuthRouter } from "../src/routes/auth.routes.js";
import { OtpService } from "../src/services/otp.service.js";
import { RegistrationStore } from "../src/services/registration.store.js";
import { SignupService } from "../src/services/signup.service.js";
import type { Server } from "node:http";

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

test("signup API validates input and verifies both channels in either order", async () => {
  if (!redisUrl) throw new Error("Redis integration test server failed to start");
  const redis = new Redis(redisUrl, { lazyConnect: true, maxRetriesPerRequest: 1 });
  await redis.connect();

  const emailCodes = new Map<string, string>();
  const phoneCodes = new Map<string, string>();
  const createdUsers: Array<{ email: string; phoneNumber: string }> = [];
  const registrations = new RegistrationStore(redis);
  const signup = new SignupService(
    registrations,
    new OtpService(registrations, "test-otp-hmac-secret-with-at-least-32-characters"),
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
    {
      createOrGetByContacts: async (contacts) => {
        createdUsers.push(contacts);
        return {
          id: `user-${createdUsers.length}`,
          email: contacts.email,
          phone_number: contacts.phoneNumber,
          is_active: true,
          created_at: new Date(),
        };
      },
    },
    {
      issueForUser: async (userId) => {
        assert.ok(createdUsers.length > 0);
        assert.ok(userId.startsWith("user-"));
        return {
          accessToken: "test-access-token",
          accessTokenExpiresIn: 900,
          refreshToken: "test-refresh-token",
          refreshTokenExpiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        };
      },
    },
  );
  const app = createApp(createAuthRouter(signup, {
    refresh: async () => ({
      accessToken: "test-access-token",
      accessTokenExpiresIn: 900,
      refreshToken: "test-refresh-token",
      refreshTokenExpiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    }),
  }));
  const server = app.listen(0);

  try {
    await once(server, "listening");
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const baseUrl = `http://127.0.0.1:${address.port}`;

    const invalid = await fetch(`${baseUrl}/auth/signup`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "bad", phoneNumber: "1234" }),
    });
    assert.equal(invalid.status, 400);
    assert.deepEqual(await invalid.json(), {
      success: false,
      error: {
        message: "A valid email address is required",
        code: "INVALID_CONTACT",
      },
    });

    for (const firstChannel of ["email", "phone"] as const) {
      const suffix = firstChannel === "email" ? "first" : "second";
      const email = `${suffix}@example.com`;
      const phone = firstChannel === "email" ? "+14155552671" : "+14155552672";
      const usersBeforeSignup = createdUsers.length;
      const started = await fetch(`${baseUrl}/auth/signup`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, phoneNumber: phone }),
      });
      assert.equal(started.status, 201);
      assert.equal(createdUsers.length, usersBeforeSignup);
      const startBody = await started.json() as {
        success: boolean;
        data: { registrationId: string };
      };
      assert.equal(startBody.success, true);

      const channels = firstChannel === "email" ? ["email", "phone"] : ["phone", "email"];
      const usersBeforeVerification = createdUsers.length;
      for (const [index, channel] of channels.entries()) {
        const code = channel === "email" ? emailCodes.get(email) : phoneCodes.get(phone);
        assert.ok(code);
        const verified = await fetch(
          `${baseUrl}/auth/signup/${startBody.data.registrationId}/verify/${channel}`,
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ code }),
          },
        );
        assert.equal(verified.status, 200);
        const verificationBody = await verified.json() as {
          success: boolean;
          data: {
            verified: boolean;
            registrationComplete: boolean;
            tokens?: {
              accessToken: string;
              accessTokenExpiresIn: number;
              refreshToken: string;
              refreshTokenExpiresAt: string;
            };
          };
        };
        assert.equal(verificationBody.success, true);
        assert.equal(verificationBody.data.verified, true);
        assert.equal(verificationBody.data.registrationComplete, index === 1);
        if (index === 1) {
          assert.equal(verificationBody.data.tokens?.accessToken, "test-access-token");
          assert.equal(verificationBody.data.tokens?.accessTokenExpiresIn, 900);
          assert.equal(verificationBody.data.tokens?.refreshToken, "test-refresh-token");
          assert.ok(verificationBody.data.tokens?.refreshTokenExpiresAt);
        } else {
          assert.equal(verificationBody.data.tokens, undefined);
        }
        assert.equal(createdUsers.length, usersBeforeVerification + (index === 1 ? 1 : 0));
      }
    }
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
    await redis.quit();
  }
});
