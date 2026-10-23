import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import {
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  importSPKI,
  jwtVerify,
  type JWK,
  SignJWT,
} from "jose";
import { Redis } from "ioredis";
import { RedisMemoryServer } from "redis-memory-server";
import type { AppConfig } from "../src/config/env.js";
import { createApp } from "../src/app.js";
import { createJwksRouter } from "../src/routes/jwks.routes.js";
import { ACCESS_TOKEN_TTL_SECONDS, AuthTokenService } from "../src/services/auth-token.service.js";
import { JwksService } from "../src/services/jwks.service.js";
import { REFRESH_TOKEN_TTL_MS, RefreshTokenStore } from "../src/services/refresh-token.store.js";
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

test("issues a signed access token and an opaque refresh family with configured lifetimes", async () => {
  if (!redisUrl) throw new Error("Redis integration test server failed to start");
  const redis = new Redis(redisUrl, { lazyConnect: true, maxRetriesPerRequest: 1 });
  const keyDirectory = await mkdtemp(join(tmpdir(), "muguauth-jwt-"));
  await redis.connect();

  try {
    const kid = "test-key-1";
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256",
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    await writeFile(join(keyDirectory, `${kid}.pem`), privateKey);

    const config: Pick<
      AppConfig,
      "JWT_KEYS_DIR" | "JWT_ACTIVE_KID" | "JWT_ISSUER" | "JWT_AUDIENCE"
    > = {
      JWT_KEYS_DIR: keyDirectory,
      JWT_ACTIVE_KID: kid,
      JWT_ISSUER: "https://auth.example.com",
      JWT_AUDIENCE: "mugu-auth-clients",
    };
    const service = new AuthTokenService(new RefreshTokenStore(redis), config);
    const now = Math.floor(Date.now() / 1000);
    const issued = await service.issueForUser("user-123");
    const payload = decodeJwt(issued.accessToken);
    const header = decodeProtectedHeader(issued.accessToken);
    const verificationKey = await importSPKI(publicKey, "ES256");
    const verified = await jwtVerify(issued.accessToken, verificationKey, {
      algorithms: ["ES256"],
      issuer: config.JWT_ISSUER,
      audience: config.JWT_AUDIENCE,
    });

    assert.equal(issued.accessTokenExpiresIn, ACCESS_TOKEN_TTL_SECONDS);
    assert.equal(issued.refreshToken.length, 43);
    assert.match(issued.refreshToken, /^[A-Za-z0-9_-]+$/);
    assert.equal(header.alg, "ES256");
    assert.equal(header.kid, kid);
    assert.equal(payload.iss, config.JWT_ISSUER);
    assert.equal(payload.aud, config.JWT_AUDIENCE);
    assert.equal(payload.sub, "user-123");
    assert.equal(payload.exp! - payload.iat!, ACCESS_TOKEN_TTL_SECONDS);
    assert.ok(payload.iat! >= now && payload.iat! <= Math.floor(Date.now() / 1000));
    assert.equal(verified.payload.sub, "user-123");

    await assert.rejects(jwtVerify(issued.accessToken, verificationKey, {
      algorithms: ["ES256"],
      issuer: "https://other.example.com",
      audience: config.JWT_AUDIENCE,
    }));
    await assert.rejects(jwtVerify(issued.accessToken, verificationKey, {
      algorithms: ["ES256"],
      issuer: config.JWT_ISSUER,
      audience: "another-client",
    }));

    const unsupportedToken = await new SignJWT({})
      .setProtectedHeader({ alg: "HS256", kid })
      .setIssuer(config.JWT_ISSUER)
      .setAudience(config.JWT_AUDIENCE)
      .setSubject("user-123")
      .setIssuedAt(now)
      .setExpirationTime(now + ACCESS_TOKEN_TTL_SECONDS)
      .sign(new TextEncoder().encode("unsupported-algorithm-test-key"));
    await assert.rejects(jwtVerify(unsupportedToken, verificationKey, {
      algorithms: ["ES256"],
      issuer: config.JWT_ISSUER,
      audience: config.JWT_AUDIENCE,
    }));

    const expiry = Date.parse(issued.refreshTokenExpiresAt);
    assert.ok(expiry - Date.now() <= REFRESH_TOKEN_TTL_MS);
    assert.ok(expiry - Date.now() > REFRESH_TOKEN_TTL_MS - 5_000);

    const digest = createHash("sha256").update(issued.refreshToken).digest("hex");
    const tokenKey = `auth:refresh:token:${digest}`;
    assert.equal(await redis.exists(`auth:refresh:token:${issued.refreshToken}`), 0);
    assert.equal(await redis.hget(tokenKey, "status"), "active");
    assert.equal(await redis.hget(tokenKey, "userId"), "user-123");
    assert.ok((await redis.pttl(tokenKey)) > REFRESH_TOKEN_TTL_MS - 5_000);
    assert.ok((await redis.pttl(tokenKey)) <= REFRESH_TOKEN_TTL_MS);

    const familyId = await redis.hget(tokenKey, "familyId");
    assert.ok(familyId);
    const familyKey = `auth:refresh:family:${familyId}`;
    assert.equal(await redis.hget(familyKey, "userId"), "user-123");
    assert.equal(await redis.hget(familyKey, "revoked"), "false");
    assert.equal(await redis.hget(familyKey, "token"), null);
    assert.equal(
      await redis.sismember(`auth:refresh:family:${familyId}:tokens`, digest),
      1,
    );
  } finally {
    await redis.quit();
    await rm(keyDirectory, { recursive: true, force: true });
  }
});

test("publishes new keys before signing and retains old keys for consumer refresh", async () => {
  if (!redisUrl) throw new Error("Redis integration test server failed to start");
  const redis = new Redis(redisUrl, { lazyConnect: true, maxRetriesPerRequest: 1 });
  const keyDirectory = await mkdtemp(join(tmpdir(), "muguauth-key-rotation-"));
  await redis.connect();
  let server: Server | undefined;

  try {
    const oldKid = "old-key";
    const newKid = "new-key";
    const oldPair = generateKeyPairSync("ec", {
      namedCurve: "P-256",
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const newPair = generateKeyPairSync("ec", {
      namedCurve: "P-256",
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    await writeFile(join(keyDirectory, `${oldKid}.pem`), oldPair.privateKey);
    await writeFile(join(keyDirectory, `${oldKid}.public.pem`), oldPair.publicKey);

    const oldConfig: Pick<
      AppConfig,
      "JWT_KEYS_DIR" | "JWT_ACTIVE_KID" | "JWT_ISSUER" | "JWT_AUDIENCE"
    > = {
      JWT_KEYS_DIR: keyDirectory,
      JWT_ACTIVE_KID: oldKid,
      JWT_ISSUER: "https://auth.example.com",
      JWT_AUDIENCE: "mugu-auth-clients",
    };
    const oldTokenService = new AuthTokenService(new RefreshTokenStore(redis), oldConfig);
    const oldToken = await oldTokenService.createAccessToken("user-rotation");

    server = createApp(undefined, createJwksRouter(new JwksService(oldConfig))).listen(0);
    await once(server, "listening");
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const jwksUrl = `http://127.0.0.1:${address.port}/.well-known/jwks.json`;
    const fetchKeySet = async (): Promise<{ keys: JWK[] }> => {
      const response = await fetch(jwksUrl);
      assert.equal(response.status, 200);
      return await response.json() as { keys: JWK[] };
    };

    let cachedKeySet = await fetchKeySet();
    assert.deepEqual(cachedKeySet.keys.map((key) => key.kid), [oldKid]);

    await writeFile(join(keyDirectory, `${newKid}.public.pem`), newPair.publicKey);
    const prepublishedKeySet = await fetchKeySet();
    assert.deepEqual(
      prepublishedKeySet.keys.map((key) => key.kid),
      [newKid, oldKid],
    );
    assert.equal(oldConfig.JWT_ACTIVE_KID, oldKid);

    await new Promise<void>((resolve, reject) => {
      server?.close((error) => error ? reject(error) : resolve());
    });
    const newConfig = { ...oldConfig, JWT_ACTIVE_KID: newKid };
    await writeFile(join(keyDirectory, `${newKid}.pem`), newPair.privateKey);
    const newTokenService = new AuthTokenService(new RefreshTokenStore(redis), newConfig);
    const newToken = await newTokenService.createAccessToken("user-rotation");
    server = createApp(undefined, createJwksRouter(new JwksService(newConfig))).listen(0);
    await once(server, "listening");
    const newAddress = server.address();
    assert.ok(newAddress && typeof newAddress !== "string");
    const newJwksUrl = `http://127.0.0.1:${newAddress.port}/.well-known/jwks.json`;

    let jwksFetches = 0;
    const verifyAsConsumer = async (token: string) => {
      const kid = decodeProtectedHeader(token).kid;
      assert.equal(typeof kid, "string");
      let jwk = cachedKeySet.keys.find((key) => key.kid === kid);
      if (!jwk) {
        jwksFetches += 1;
        const response = await fetch(newJwksUrl);
        cachedKeySet = await response.json() as { keys: JWK[] };
        jwk = cachedKeySet.keys.find((key) => key.kid === kid);
      }
      assert.ok(jwk);
      return jwtVerify(token, await importJWK(jwk, "ES256"), {
        algorithms: ["ES256"],
        issuer: oldConfig.JWT_ISSUER,
        audience: oldConfig.JWT_AUDIENCE,
        clockTolerance: 60,
      });
    };

    assert.equal((await verifyAsConsumer(newToken)).payload.sub, "user-rotation");
    assert.equal(jwksFetches, 1);
    assert.equal((await verifyAsConsumer(oldToken)).payload.sub, "user-rotation");
    assert.equal(jwksFetches, 1);
    assert.deepEqual(
      cachedKeySet.keys.map((key) => key.kid).sort(),
      [newKid, oldKid].sort(),
    );
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
