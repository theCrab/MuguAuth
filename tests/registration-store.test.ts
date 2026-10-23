import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { Redis } from "ioredis";
import { RedisMemoryServer } from "redis-memory-server";
import {
  InvalidRegistrationInputError,
  normalizeRegistrationContacts,
  REGISTRATION_TTL_SECONDS,
  type RegistrationContacts,
  RegistrationStore,
} from "../src/services/registration.store.js";
import {
  OTP_MAX_ATTEMPTS,
  OTP_MAX_SENDS_PER_CHANNEL,
  OTP_RESEND_COOLDOWN_MS,
  OTP_TTL_MS,
  OtpService,
} from "../src/services/otp.service.js";
import { OtpDeliveryError } from "../src/services/otp-delivery.error.js";
import { SignupService } from "../src/services/signup.service.js";

let redisServer: RedisMemoryServer | undefined;
let testRedisUrl: string;

before(async () => {
  redisServer = await RedisMemoryServer.create({
    autoStart: true,
    binary: { version: "7.4.2" },
  });
  testRedisUrl = `redis://${await redisServer.getHost()}:${await redisServer.getPort()}`;
});

after(async () => {
  await redisServer?.stop();
});

test("normalizes valid signup contacts", () => {
  assert.deepEqual(
    normalizeRegistrationContacts(" Person@Example.COM ", "+14155552671"),
    { email: "person@example.com", phoneNumber: "+14155552671" },
  );
});

test("rejects invalid email and phone input", () => {
  assert.throws(
    () => normalizeRegistrationContacts("not-an-email", "+14155552671"),
    InvalidRegistrationInputError,
  );
  assert.throws(
    () => normalizeRegistrationContacts("person@example.com", "12345"),
    InvalidRegistrationInputError,
  );
});

test("stores temporary registration with unverified contacts and a 15-minute TTL", async () => {
  if (!testRedisUrl) throw new Error("Redis integration test server failed to start");
  const redis = new Redis(testRedisUrl, {
    lazyConnect: true,
    maxRetriesPerRequest: 1,
  });
  await redis.connect();

  try {
    const store = new RegistrationStore(redis);
    const contacts = normalizeRegistrationContacts("person@example.com", "+14155552671");
    const id = await store.create(contacts);
    const registration = await store.get(id);

    assert.deepEqual(registration, {
      id,
      ...contacts,
      emailVerified: false,
      phoneVerified: false,
    });
    assert.ok((await redis.ttl(`signup:registration:${id}`)) <= REGISTRATION_TTL_SECONDS);
  } finally {
    await redis.quit();
  }
});

test("OTP challenges expire, enforce limits, and are consumed once", async () => {
  if (!testRedisUrl) throw new Error("Redis integration test server failed to start");
  const redis = new Redis(testRedisUrl, {
    lazyConnect: true,
    maxRetriesPerRequest: 1,
  });
  await redis.connect();

  try {
    const store = new RegistrationStore(redis);
    const service = new OtpService(store, "test-otp-hmac-secret-with-at-least-32-characters");
    const id = await store.create(
      normalizeRegistrationContacts("person@example.com", "+14155552671"),
    );
    const now = Date.now();
    const first = await service.issue(id, "email", now);
    assert.equal(first.result, "issued");
    assert.match(first.code ?? "", /^\d{6}$/);
    const firstWrongCode = first.code === "000000" ? "000001" : "000000";

    const key = `signup:registration:${id}`;
    const savedChallenge = await redis.hgetall(key);
    assert.notEqual(savedChallenge.emailChallengeHash, first.code);
    assert.ok(savedChallenge.emailChallengeHash);
    assert.equal(Number(savedChallenge.emailChallengeExpiresAt), now + OTP_TTL_MS);

    for (let attempt = 0; attempt < OTP_MAX_ATTEMPTS; attempt += 1) {
      assert.equal(await service.verify(id, "email", firstWrongCode, now + 1), "invalid");
    }
    assert.equal(
      await service.verify(id, "email", firstWrongCode, now + 2),
      "attempt_limit",
    );
    assert.equal((await service.issue(id, "email", now + 3)).result, "cooldown");

    const resendTime = now + OTP_RESEND_COOLDOWN_MS + 1;
    const resent = await service.issue(id, "email", resendTime);
    assert.equal(resent.result, "issued");
    if (resent.code !== first.code) {
      assert.equal(await service.verify(id, "email", first.code ?? "", resendTime), "invalid");
    }

    const concurrentResults = await Promise.all([
      service.verify(id, "email", resent.code ?? "", resendTime),
      service.verify(id, "email", resent.code ?? "", resendTime),
    ]);
    assert.equal(concurrentResults.filter((result) => result === "verified").length, 1);
    assert.equal(concurrentResults.filter((result) => result === "already_verified").length, 1);

    const phone = await service.issue(id, "phone", resendTime + OTP_RESEND_COOLDOWN_MS + 1);
    assert.equal(phone.result, "issued");
    assert.equal(
      await service.verify(id, "phone", phone.code ?? "", resendTime + OTP_RESEND_COOLDOWN_MS + 1),
      "registration_complete",
    );
    assert.equal((await service.issue(id, "email", resendTime * 2)).result, "already_verified");

    const anotherId = await store.create(
      normalizeRegistrationContacts("second@example.com", "+14155552672"),
    );
    const expiring = await service.issue(anotherId, "email", now);
    assert.equal(expiring.result, "issued");
    assert.equal(
      await service.verify(anotherId, "email", expiring.code ?? "", now + OTP_TTL_MS),
      "expired",
    );

    const lastId = await store.create(
      normalizeRegistrationContacts("third@example.com", "+14155552673"),
    );
    await service.issue(lastId, "email", now);
    await service.issue(lastId, "email", now + OTP_RESEND_COOLDOWN_MS + 1);
    assert.equal(
      (await service.issue(
        lastId,
        "email",
        now + (OTP_RESEND_COOLDOWN_MS + 1) * 2,
      )).result,
      "issued",
    );
    assert.equal(
      (await service.issue(
        lastId,
        "email",
        now + (OTP_RESEND_COOLDOWN_MS + 1) * 3,
      )).result,
      "send_limit",
    );
    assert.equal(OTP_MAX_SENDS_PER_CHANNEL, 3);

    await redis.del(key, `signup:registration:${anotherId}`, `signup:registration:${lastId}`);
  } finally {
    await redis.quit();
  }
});

test("signup removes pending state when either delivery provider fails", async () => {
  if (!testRedisUrl) throw new Error("Redis integration test server failed to start");
  const redis = new Redis(testRedisUrl, {
    lazyConnect: true,
    maxRetriesPerRequest: 1,
  });
  await redis.connect();

  try {
    class TrackingRegistrationStore extends RegistrationStore {
      createdId: string | undefined;

      override async create(contacts: RegistrationContacts): Promise<string> {
        this.createdId = await super.create(contacts);
        return this.createdId;
      }
    }
    const registrations = new TrackingRegistrationStore(redis);
    const otp = new OtpService(
      registrations,
      "test-otp-hmac-secret-with-at-least-32-characters",
    );
    const signup = new SignupService(
      registrations,
      otp,
      { sendVerificationCode: async () => undefined },
      { sendVerificationCode: async () => { throw new Error("provider response includes private details"); } },
      { createOrGetByContacts: async () => { throw new Error("not used by this test"); } },
      { issueForUser: async () => { throw new Error("not used by this test"); } },
    );

    await assert.rejects(
      signup.start("person@example.com", "+14155552671"),
      (error: Error) => error instanceof OtpDeliveryError
        && !error.message.includes("private details"),
    );
    assert.ok(registrations.createdId);
    assert.equal(await redis.exists(`signup:registration:${registrations.createdId}`), 0);
  } finally {
    await redis.quit();
  }
});
