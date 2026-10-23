import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { importPKCS8, SignJWT } from "jose";
import type { Server } from "node:http";
import type { AppConfig } from "../src/config/env.js";
import { createApp } from "../src/app.js";
import { createAuthMiddleware } from "../src/middlewares/auth.middleware.js";
import { createProtectedRouter } from "../src/routes/protected.routes.js";
import { JwksService } from "../src/services/jwks.service.js";

test("protected account endpoint validates ES256 and checks current account status", async () => {
  const keyDirectory = await mkdtemp(join(tmpdir(), "muguauth-middleware-"));
  let server: Server | undefined;

  try {
    const kid = "middleware-key";
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256",
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
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
    const signingKey = await importPKCS8(privateKey, "ES256");
    const now = Math.floor(Date.now() / 1000);
    const sign = (
      subject: string,
      claims: { issuer?: string; audience?: string; issuedAt?: number; expiresAt?: number } = {},
    ) => new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid })
      .setIssuer(claims.issuer ?? config.JWT_ISSUER)
      .setAudience(claims.audience ?? config.JWT_AUDIENCE)
      .setSubject(subject)
      .setIssuedAt(claims.issuedAt ?? now)
      .setExpirationTime(claims.expiresAt ?? now + 900);

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
    const app = createApp(
      undefined,
      undefined,
      createProtectedRouter(createAuthMiddleware(users, new JwksService(config), config)),
    );
    server = app.listen(0);
    await once(server, "listening");
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const url = `http://127.0.0.1:${address.port}/auth/me`;

    const unauthenticated = await fetch(url);
    assert.equal(unauthenticated.status, 401);

    const token = await (await sign("user-123")).sign(signingKey);
    const activeResponse = await fetch(url, {
      headers: { authorization: `Bearer ${token}` },
    });
    assert.equal(activeResponse.status, 200);
    assert.deepEqual(await activeResponse.json(), {
      success: true,
      data: {
        user: {
          id: "user-123",
          email: "person@example.com",
          phoneNumber: "+14155552671",
          isActive: true,
        },
      },
    });

    userActive = false;
    const inactiveResponse = await fetch(url, {
      headers: { authorization: `Bearer ${token}` },
    });
    assert.equal(inactiveResponse.status, 403);
    assert.deepEqual(await inactiveResponse.json(), {
      success: false,
      error: {
        message: "Account is inactive",
        code: "ACCOUNT_INACTIVE",
      },
    });
    userActive = true;

    const wrongIssuer = await (await sign("user-123", { issuer: "https://other.example.com" }))
      .sign(signingKey);
    const wrongAudience = await (await sign("user-123", { audience: "other-client" }))
      .sign(signingKey);
    const expired = await (await sign("user-123", {
      issuedAt: now - 901,
      expiresAt: now - 1,
    })).sign(signingKey);
    const unsupportedAlgorithm = await new SignJWT({})
      .setProtectedHeader({ alg: "HS256", kid })
      .setIssuer(config.JWT_ISSUER)
      .setAudience(config.JWT_AUDIENCE)
      .setSubject("user-123")
      .setIssuedAt(now)
      .setExpirationTime(now + 900)
      .sign(new TextEncoder().encode("not-an-ES256-key"));

    for (const invalidToken of [wrongIssuer, wrongAudience, expired, unsupportedAlgorithm]) {
      const response = await fetch(url, {
        headers: { authorization: `Bearer ${invalidToken}` },
      });
      assert.equal(response.status, 401);
    }

    const unknownKid = await new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: "unknown-key" })
      .setIssuer(config.JWT_ISSUER)
      .setAudience(config.JWT_AUDIENCE)
      .setSubject("user-123")
      .setIssuedAt(now)
      .setExpirationTime(now + 900)
      .sign(signingKey);
    const unknownKeyResponse = await fetch(url, {
      headers: { authorization: `Bearer ${unknownKid}` },
    });
    assert.equal(unknownKeyResponse.status, 401);
  } finally {
    if (server?.listening) {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    }
    await rm(keyDirectory, { recursive: true, force: true });
  }
});
