import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { importPKCS8, SignJWT } from "jose";
import type { AppConfig } from "../config/env.js";
import { RefreshTokenStore } from "./refresh-token.store.js";

export const ACCESS_TOKEN_TTL_SECONDS = 15 * 60;

export interface IssuedAuthTokens {
  accessToken: string;
  accessTokenExpiresIn: number;
  refreshToken: string;
  refreshTokenExpiresAt: string;
}

export interface AuthTokenIssuer {
  issueForUser(userId: string): Promise<IssuedAuthTokens>;
}

export class AuthTokenService implements AuthTokenIssuer {
  constructor(
    private readonly refreshTokens: RefreshTokenStore,
    private readonly config: Pick<
      AppConfig,
      "JWT_KEYS_DIR" | "JWT_ACTIVE_KID" | "JWT_ISSUER" | "JWT_AUDIENCE"
    >,
  ) {}

  async issueForUser(userId: string): Promise<IssuedAuthTokens> {
    const accessToken = await this.createAccessToken(userId);
    const refreshFamily = await this.refreshTokens.createFamily(userId);

    return {
      accessToken,
      accessTokenExpiresIn: ACCESS_TOKEN_TTL_SECONDS,
      refreshToken: refreshFamily.token,
      refreshTokenExpiresAt: refreshFamily.expiresAt.toISOString(),
    };
  }

  async createAccessToken(userId: string): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const privateKeyPath = join(
      this.config.JWT_KEYS_DIR,
      `${this.config.JWT_ACTIVE_KID}.pem`,
    );
    const privateKeyPem = await readFile(privateKeyPath, "utf8");
    const privateKey = await importPKCS8(privateKeyPem, "ES256");
    const accessToken = await new SignJWT({})
      .setProtectedHeader({
        alg: "ES256",
        kid: this.config.JWT_ACTIVE_KID,
        typ: "JWT",
      })
      .setIssuer(this.config.JWT_ISSUER)
      .setAudience(this.config.JWT_AUDIENCE)
      .setSubject(userId)
      .setIssuedAt(now)
      .setExpirationTime(now + ACCESS_TOKEN_TTL_SECONDS)
      .sign(privateKey);

    return accessToken;
  }
}
