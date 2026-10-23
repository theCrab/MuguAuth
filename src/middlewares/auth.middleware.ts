import type { RequestHandler } from "express";
import { decodeProtectedHeader, errors, jwtVerify } from "jose";
import type { AppConfig } from "../config/env.js";
import type { UserStatusRepository } from "../models/user.model.js";
import { ApiError } from "../services/api.error.js";
import { JwksService } from "../services/jwks.service.js";

export function createAuthMiddleware(
  users: UserStatusRepository,
  jwks: JwksService,
  config: Pick<AppConfig, "JWT_ISSUER" | "JWT_AUDIENCE">,
): RequestHandler {
  return async (request, response, next) => {
    const authorization = request.header("authorization");
    const match = authorization?.match(/^Bearer ([^\s]+)$/i);
    if (!match) {
      throw new ApiError(401, "AUTHENTICATION_REQUIRED", "A bearer access token is required");
    }

    const token = match[1];
    let header: ReturnType<typeof decodeProtectedHeader>;
    try {
      header = decodeProtectedHeader(token);
    } catch (error) {
      if (error instanceof errors.JOSEError) throw invalidAccessToken();
      throw error;
    }
    if (header.alg !== "ES256" || typeof header.kid !== "string") {
      throw invalidAccessToken();
    }

    const verificationKey = await jwks.getVerificationKey(header.kid);
    if (!verificationKey) throw invalidAccessToken();

    let payload: Awaited<ReturnType<typeof jwtVerify>>["payload"];
    try {
      ({ payload } = await jwtVerify(token, verificationKey, {
        algorithms: ["ES256"],
        issuer: config.JWT_ISSUER,
        audience: config.JWT_AUDIENCE,
      }));
    } catch (error) {
      if (error instanceof errors.JOSEError) throw invalidAccessToken();
      throw error;
    }

    if (
      typeof payload.sub !== "string"
      || payload.sub.length === 0
      || typeof payload.iat !== "number"
      || typeof payload.exp !== "number"
    ) {
      throw invalidAccessToken();
    }

    const user = await users.findById(payload.sub);
    if (!user) throw invalidAccessToken();
    if (!user.is_active) {
      throw new ApiError(403, "ACCOUNT_INACTIVE", "Account is inactive");
    }

    request.authenticatedUser = user;
    next();
  };
}

function invalidAccessToken(): ApiError {
  return new ApiError(401, "INVALID_ACCESS_TOKEN", "Access token is invalid or expired");
}
