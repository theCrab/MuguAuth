import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { exportJWK, importSPKI, type JWK } from "jose";
import type { AppConfig } from "../config/env.js";

const publicKeyFilePattern = /^([A-Za-z0-9._-]{1,128})\.public\.pem$/;
const keyIdPattern = /^[A-Za-z0-9._-]{1,128}$/;

export class JwksService {
  constructor(
    private readonly config: Pick<AppConfig, "JWT_KEYS_DIR" | "JWT_ACTIVE_KID">,
  ) {}

  async getKeySet(): Promise<{ keys: JWK[] }> {
    const files = await readdir(this.config.JWT_KEYS_DIR);
    const keyFiles = files
      .map((fileName) => {
        const match = publicKeyFilePattern.exec(fileName);
        return match ? { fileName, kid: match[1] } : undefined;
      })
      .filter((entry): entry is { fileName: string; kid: string } => entry !== undefined)
      .sort((left, right) => left.kid.localeCompare(right.kid));

    if (!keyFiles.some(({ kid }) => kid === this.config.JWT_ACTIVE_KID)) {
      throw new Error("The active JWT signing key has no published public key");
    }

    const keys = await Promise.all(keyFiles.map(async ({ fileName, kid }) => {
      const publicKey = await this.getVerificationKey(kid);
      if (!publicKey) throw new Error(`The public key for '${kid}' is missing`);
      const jwk = await exportJWK(publicKey);
      if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) {
        throw new Error(`The public key for '${kid}' is not a valid ES256 key`);
      }

      return {
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y,
        kid,
        alg: "ES256",
        use: "sig",
      };
    }));

    return { keys };
  }

  async getVerificationKey(kid: string): Promise<CryptoKey | null> {
    if (!keyIdPattern.test(kid)) return null;

    let pem: string;
    try {
      pem = await readFile(join(this.config.JWT_KEYS_DIR, `${kid}.public.pem`), "utf8");
    } catch (error) {
      if (
        error instanceof Error
        && "code" in error
        && error.code === "ENOENT"
      ) {
        return null;
      }
      throw error;
    }

    return importSPKI(pem, "ES256");
  }
}
