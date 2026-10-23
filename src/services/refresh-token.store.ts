import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { Redis as RedisClient } from "ioredis";

export const REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;
export const REFRESH_TOKEN_TTL_MS = REFRESH_TOKEN_TTL_SECONDS * 1000;
const refreshTokenPattern = /^[A-Za-z0-9_-]{43}$/;

const rotateRefreshTokenScript = `
  if redis.call("EXISTS", KEYS[1]) == 0 then return 0 end
  if redis.call("EXISTS", KEYS[2]) == 0 then return 0 end

  local familyId = redis.call("HGET", KEYS[1], "familyId")
  if familyId ~= ARGV[1] then return 0 end
  local status = redis.call("HGET", KEYS[1], "status")
  if status == "used" then
    redis.call("HSET", KEYS[2], "revoked", "true")
    return -2
  end
  if status ~= "active" then return 0 end
  if redis.call("HGET", KEYS[2], "revoked") == "true" then return 0 end

  local expiresAt = tonumber(redis.call("HGET", KEYS[2], "expiresAt") or "0")
  if expiresAt == 0 or tonumber(ARGV[5]) >= expiresAt then return 0 end
  if expiresAt ~= tonumber(ARGV[4]) then return 0 end
  local userId = redis.call("HGET", KEYS[1], "userId")
  if not userId or userId ~= redis.call("HGET", KEYS[2], "userId") then return 0 end
  if userId ~= ARGV[2] then return 0 end

  redis.call("HSET", KEYS[1], "status", "used")
  redis.call("HSET", KEYS[4],
    "familyId", familyId,
    "userId", userId,
    "status", "active")
  redis.call("PEXPIREAT", KEYS[4], expiresAt)
  redis.call("SADD", KEYS[3], ARGV[3])
  redis.call("PEXPIREAT", KEYS[3], expiresAt)
  return 1
`;

export interface CreatedRefreshFamily {
  familyId: string;
  token: string;
  expiresAt: Date;
}

export interface RefreshTokenRecord {
  familyId: string;
  userId: string;
  status: "active" | "used";
  expiresAt: Date;
}

export type RefreshRotationResult =
  | { status: "rotated"; familyId: string; token: string; expiresAt: Date }
  | { status: "reused" | "invalid" };

export class RefreshTokenStore {
  constructor(private readonly redis: RedisClient) {}

  async createFamily(userId: string): Promise<CreatedRefreshFamily> {
    const familyId = randomUUID();
    const token = randomBytes(32).toString("base64url");
    const digest = this.digest(token);
    const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);
    const familyKey = `auth:refresh:family:${familyId}`;
    const tokenKey = `auth:refresh:token:${digest}`;
    const familyTokensKey = `auth:refresh:family:${familyId}:tokens`;

    const result = await this.redis
      .multi()
      .hset(familyKey, {
        userId,
        expiresAt: expiresAt.getTime().toString(),
        revoked: "false",
      })
      .pexpireat(familyKey, expiresAt.getTime())
      .hset(tokenKey, { familyId, userId, status: "active" })
      .pexpireat(tokenKey, expiresAt.getTime())
      .sadd(familyTokensKey, digest)
      .pexpireat(familyTokensKey, expiresAt.getTime())
      .exec();

    if (!result) throw new Error("Redis did not complete refresh family creation");
    for (const [error] of result) {
      if (error) throw error;
    }

    return { familyId, token, expiresAt };
  }

  async inspect(token: string): Promise<RefreshTokenRecord | null> {
    if (!refreshTokenPattern.test(token)) return null;
    const digest = this.digest(token);
    const tokenValues = await this.redis.hmget(
      `auth:refresh:token:${digest}`,
      "familyId",
      "userId",
      "status",
    );
    const [familyId, userId, status] = tokenValues;
    if (!familyId || !userId || (status !== "active" && status !== "used")) return null;

    const familyValues = await this.redis.hmget(
      `auth:refresh:family:${familyId}`,
      "expiresAt",
      "revoked",
    );
    const [expiresAtValue, revoked] = familyValues;
    const expiresAtMs = Number(expiresAtValue);
    if (
      !Number.isSafeInteger(expiresAtMs)
      || expiresAtMs <= Date.now()
      || revoked !== "false"
    ) {
      return null;
    }

    return {
      familyId,
      userId,
      status,
      expiresAt: new Date(expiresAtMs),
    };
  }

  async rotate(token: string, record: RefreshTokenRecord): Promise<RefreshRotationResult> {
    if (!refreshTokenPattern.test(token)) return { status: "invalid" };

    const digest = this.digest(token);
    const successor = randomBytes(32).toString("base64url");
    const successorDigest = this.digest(successor);
    const result = Number(await this.redis.eval(
      rotateRefreshTokenScript,
      4,
      `auth:refresh:token:${digest}`,
      `auth:refresh:family:${record.familyId}`,
      `auth:refresh:family:${record.familyId}:tokens`,
      `auth:refresh:token:${successorDigest}`,
      record.familyId,
      record.userId,
      successorDigest,
      record.expiresAt.getTime(),
      Date.now(),
    ));

    if (result === 1) {
      return {
        status: "rotated",
        familyId: record.familyId,
        token: successor,
        expiresAt: record.expiresAt,
      };
    }
    if (result === -2) return { status: "reused" };
    return { status: "invalid" };
  }

  private digest(token: string): string {
    return createHash("sha256").update(token).digest("hex");
  }
}
