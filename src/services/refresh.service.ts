import type { UserStatusRepository } from "../models/user.model.js";
import { ApiError } from "./api.error.js";
import { ACCESS_TOKEN_TTL_SECONDS, AuthTokenService } from "./auth-token.service.js";
import type { IssuedAuthTokens } from "./auth-token.service.js";
import { RefreshTokenStore } from "./refresh-token.store.js";

export interface RefreshTokenRefresher {
  refresh(refreshToken: string): Promise<IssuedAuthTokens>;
}

export class RefreshService implements RefreshTokenRefresher {
  constructor(
    private readonly refreshTokens: RefreshTokenStore,
    private readonly tokens: AuthTokenService,
    private readonly users: UserStatusRepository,
  ) {}

  async refresh(refreshToken: string): Promise<IssuedAuthTokens> {
    const record = await this.refreshTokens.inspect(refreshToken);
    if (!record) throw this.invalidRefreshToken();

    if (record.status === "used") {
      await this.refreshTokens.rotate(refreshToken, record);
      throw this.invalidRefreshToken();
    }

    const user = await this.users.findById(record.userId);
    if (!user) throw this.invalidRefreshToken();
    if (!user.is_active) {
      throw new ApiError(403, "ACCOUNT_INACTIVE", "Account is inactive");
    }

    const accessToken = await this.tokens.createAccessToken(user.id);
    const rotation = await this.refreshTokens.rotate(refreshToken, record);
    if (rotation.status !== "rotated") throw this.invalidRefreshToken();

    return {
      accessToken,
      accessTokenExpiresIn: ACCESS_TOKEN_TTL_SECONDS,
      refreshToken: rotation.token,
      refreshTokenExpiresAt: rotation.expiresAt.toISOString(),
    };
  }

  private invalidRefreshToken(): ApiError {
    return new ApiError(401, "INVALID_REFRESH_TOKEN", "Refresh token is invalid or expired");
  }
}
