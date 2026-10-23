import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { AppConfig } from "../src/config/env.js";
import { createApp } from "../src/app.js";
import { createJwksRouter } from "../src/routes/jwks.routes.js";
import { JwksService } from "../src/services/jwks.service.js";

test("publishes public ES256 keys with bounded caching and no private key material", async () => {
  const keyDirectory = await mkdtemp(join(tmpdir(), "muguauth-jwks-"));
  const activeKid = "active-key";
  const retiredKid = "retired-key";
  const activePair = generateKeyPairSync("ec", {
    namedCurve: "P-256",
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  const retiredPair = generateKeyPairSync("ec", {
    namedCurve: "P-256",
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });

  try {
    await writeFile(join(keyDirectory, `${activeKid}.pem`), activePair.privateKey);
    await writeFile(join(keyDirectory, `${activeKid}.public.pem`), activePair.publicKey);
    await writeFile(join(keyDirectory, `${retiredKid}.pem`), retiredPair.privateKey);
    await writeFile(join(keyDirectory, `${retiredKid}.public.pem`), retiredPair.publicKey);
    await writeFile(join(keyDirectory, "unrelated.txt"), "not a signing key");

    const config: Pick<AppConfig, "JWT_KEYS_DIR" | "JWT_ACTIVE_KID"> = {
      JWT_KEYS_DIR: keyDirectory,
      JWT_ACTIVE_KID: activeKid,
    };
    const app = createApp(undefined, createJwksRouter(new JwksService(config)));
    const server = app.listen(0);

    try {
      await once(server, "listening");
      const address = server.address();
      assert.ok(address && typeof address !== "string");
      const response = await fetch(`http://127.0.0.1:${address.port}/.well-known/jwks.json`);
      assert.equal(response.status, 200);
      assert.match(response.headers.get("content-type") ?? "", /application\/json/);
      assert.equal(
        response.headers.get("cache-control"),
        "public, max-age=300, must-revalidate",
      );

      const document = await response.json() as { keys: Array<Record<string, unknown>> };
      assert.deepEqual(
        document.keys.map((key) => key.kid).sort(),
        [activeKid, retiredKid],
      );
      for (const key of document.keys) {
        assert.equal(key.kty, "EC");
        assert.equal(key.crv, "P-256");
        assert.equal(key.alg, "ES256");
        assert.equal(key.use, "sig");
        assert.equal(typeof key.x, "string");
        assert.equal(typeof key.y, "string");
        assert.equal("d" in key, false);
      }
      assert.equal(JSON.stringify(document).includes("PRIVATE KEY"), false);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    }
  } finally {
    await rm(keyDirectory, { recursive: true, force: true });
  }
});
