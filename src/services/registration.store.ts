import { randomUUID } from "node:crypto";
import { parsePhoneNumberFromString } from "libphonenumber-js";
import { z } from "zod";
import type { Redis as RedisClient } from "ioredis";
import { ApiError } from "./api.error.js";

export const REGISTRATION_TTL_SECONDS = 15 * 60;
const registrationKeyPrefix = "signup:registration:";

export interface RegistrationContacts {
  email: string;
  phoneNumber: string;
}

export interface PendingRegistration extends RegistrationContacts {
  id: string;
  emailVerified: boolean;
  phoneVerified: boolean;
}

export type VerificationChannel = "email" | "phone";

export type ChallengeIssueResult =
  | "issued"
  | "expired"
  | "already_verified"
  | "cooldown"
  | "send_limit";

export type ChallengeVerificationResult =
  | "verified"
  | "registration_complete"
  | "invalid"
  | "expired"
  | "attempt_limit"
  | "already_verified";

const issueChallengeScript = `
  if redis.call("EXISTS", KEYS[1]) == 0 then return -1 end
  local verifiedField = ARGV[1] .. "Verified"
  if redis.call("HGET", KEYS[1], verifiedField) == "true" then return -2 end

  local sentAtField = ARGV[1] .. "ChallengeSentAt"
  local sendsField = ARGV[1] .. "ChallengeSendCount"
  local sentAt = tonumber(redis.call("HGET", KEYS[1], sentAtField) or "0")
  local now = tonumber(ARGV[3])
  if sentAt > 0 and now - sentAt < tonumber(ARGV[5]) then return -3 end
  local sends = tonumber(redis.call("HGET", KEYS[1], sendsField) or "0")
  if sends >= tonumber(ARGV[6]) then return -4 end

  redis.call("HSET", KEYS[1],
    ARGV[1] .. "ChallengeHash", ARGV[2],
    ARGV[1] .. "ChallengeExpiresAt", now + tonumber(ARGV[4]),
    ARGV[1] .. "ChallengeAttempts", 0,
    sentAtField, now)
  redis.call("HINCRBY", KEYS[1], sendsField, 1)
  return 1
`;

const verifyChallengeScript = `
  if redis.call("EXISTS", KEYS[1]) == 0 then return -1 end
  local verifiedField = ARGV[1] .. "Verified"
  if redis.call("HGET", KEYS[1], verifiedField) == "true" then return -2 end
  local hashField = ARGV[1] .. "ChallengeHash"
  local expiresAt = tonumber(redis.call("HGET", KEYS[1], ARGV[1] .. "ChallengeExpiresAt") or "0")
  if expiresAt == 0 or tonumber(ARGV[3]) >= expiresAt then return -1 end

  local attemptsField = ARGV[1] .. "ChallengeAttempts"
  local attempts = redis.call("HINCRBY", KEYS[1], attemptsField, 1)
  if attempts > tonumber(ARGV[4]) then return -3 end
  if redis.call("HGET", KEYS[1], hashField) ~= ARGV[2] then return 0 end

  redis.call("HSET", KEYS[1], verifiedField, "true")
  redis.call("HDEL", KEYS[1], hashField, ARGV[1] .. "ChallengeExpiresAt")
  if redis.call("HGET", KEYS[1], "emailVerified") == "true"
     and redis.call("HGET", KEYS[1], "phoneVerified") == "true" then
    return 2
  end
  return 1
`;

const clearChallengeScript = `
  if redis.call("EXISTS", KEYS[1]) == 0 then return 0 end
  redis.call("HDEL", KEYS[1],
    ARGV[1] .. "ChallengeHash",
    ARGV[1] .. "ChallengeExpiresAt",
    ARGV[1] .. "ChallengeAttempts")
  return 1
`;

export class InvalidRegistrationInputError extends ApiError {
  constructor(message: string) {
    super(400, "INVALID_CONTACT", message);
    this.name = "InvalidRegistrationInputError";
  }
}

export function normalizeRegistrationContacts(
  emailInput: string,
  phoneInput: string,
): RegistrationContacts {
  const email = emailInput.trim().toLowerCase();
  if (!z.string().email().safeParse(email).success) {
    throw new InvalidRegistrationInputError("A valid email address is required");
  }

  const phone = parsePhoneNumberFromString(phoneInput.trim());
  if (!phone?.isValid()) {
    throw new InvalidRegistrationInputError("A valid international phone number is required");
  }

  return { email, phoneNumber: phone.number };
}

export class RegistrationStore {
  constructor(private readonly redis: RedisClient) {}

  async create(contacts: RegistrationContacts): Promise<string> {
    const id = randomUUID();
    const key = this.key(id);
    const result = await this.redis
      .multi()
      .hset(key, {
        email: contacts.email,
        phoneNumber: contacts.phoneNumber,
        emailVerified: "false",
        phoneVerified: "false",
      })
      .expire(key, REGISTRATION_TTL_SECONDS)
      .exec();

    if (!result) {
      throw new Error("Redis did not complete registration creation");
    }
    for (const [error] of result) {
      if (error) throw error;
    }

    return id;
  }

  async get(id: string): Promise<PendingRegistration | null> {
    const values = await this.redis.hgetall(this.key(id));
    if (!values.email || !values.phoneNumber) return null;

    return {
      id,
      email: values.email,
      phoneNumber: values.phoneNumber,
      emailVerified: values.emailVerified === "true",
      phoneVerified: values.phoneVerified === "true",
    };
  }

  async issueChallenge(
    id: string,
    channel: VerificationChannel,
    digest: string,
    now: number,
    options: { challengeTtlMs: number; cooldownMs: number; maxSends: number },
  ): Promise<ChallengeIssueResult> {
    const result = Number(await this.redis.eval(
      issueChallengeScript,
      1,
      this.key(id),
      channel,
      digest,
      now,
      options.challengeTtlMs,
      options.cooldownMs,
      options.maxSends,
    ));
    if (result === 1) return "issued";
    if (result === -1) return "expired";
    if (result === -2) return "already_verified";
    if (result === -3) return "cooldown";
    return "send_limit";
  }

  async verifyChallenge(
    id: string,
    channel: VerificationChannel,
    digest: string,
    now: number,
    maxAttempts: number,
  ): Promise<ChallengeVerificationResult> {
    const result = Number(await this.redis.eval(
      verifyChallengeScript,
      1,
      this.key(id),
      channel,
      digest,
      now,
      maxAttempts,
    ));
    if (result === 1) return "verified";
    if (result === 2) return "registration_complete";
    if (result === 0) return "invalid";
    if (result === -2) return "already_verified";
    if (result === -3) return "attempt_limit";
    return "expired";
  }

  async clearChallenge(id: string, channel: VerificationChannel): Promise<boolean> {
    return Number(await this.redis.eval(
      clearChallengeScript,
      1,
      this.key(id),
      channel,
    )) === 1;
  }

  async delete(id: string): Promise<boolean> {
    return (await this.redis.del(this.key(id))) === 1;
  }

  private key(id: string): string {
    return `${registrationKeyPrefix}${id}`;
  }
}
