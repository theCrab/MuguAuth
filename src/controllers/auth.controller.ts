import { z } from "zod";
import type { RequestHandler } from "express";
import { ApiError } from "../services/api.error.js";
import type { VerificationChannel } from "../services/registration.store.js";
import type { RefreshTokenRefresher } from "../services/refresh.service.js";
import { SignupService } from "../services/signup.service.js";

const signupBodySchema = z.object({
  email: z.string(),
  phoneNumber: z.string(),
});

const verificationBodySchema = z.object({
  code: z.string().regex(/^\d{6}$/),
});

const refreshBodySchema = z.object({
  refreshToken: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
});

const registrationIdSchema = z.string().uuid();

function parseRegistrationId(value: unknown): string {
  const parsed = registrationIdSchema.safeParse(value);
  if (!parsed.success) {
    throw new ApiError(400, "INVALID_REGISTRATION_ID", "A valid registration ID is required");
  }
  return parsed.data;
}

function verificationHandler(
  signup: SignupService,
  channel: VerificationChannel,
): RequestHandler {
  return async (request, response) => {
    const registrationId = parseRegistrationId(request.params.registrationId ?? "");
    const body = verificationBodySchema.safeParse(request.body);
    if (!body.success) {
      throw new ApiError(400, "INVALID_CODE", "A six-digit verification code is required");
    }

    const verification = await signup.verify(registrationId, channel, body.data.code);
    const result = verification.result;
    if (result === "invalid") {
      throw new ApiError(400, "INVALID_CODE", "Verification code is invalid");
    }
    if (result === "expired") {
      throw new ApiError(410, "CHALLENGE_EXPIRED", "Verification code or registration expired");
    }
    if (result === "attempt_limit") {
      throw new ApiError(429, "OTP_ATTEMPT_LIMIT", "Too many verification attempts");
    }
    if (result === "already_verified") {
      throw new ApiError(409, "CHANNEL_ALREADY_VERIFIED", "Contact method is already verified");
    }

    response.status(200).json({
      success: true,
      data: {
        verified: true,
        registrationComplete: result === "registration_complete",
        ...(verification.tokens ? { tokens: verification.tokens } : {}),
      },
    });
  };
}

function resendHandler(signup: SignupService, channel: VerificationChannel): RequestHandler {
  return async (request, response) => {
    const registrationId = parseRegistrationId(request.params.registrationId ?? "");
    await signup.resend(registrationId, channel);
    response.status(202).json({
      success: true,
      data: { sent: true },
    });
  };
}

export function createAuthController(signup: SignupService) {
  const start: RequestHandler = async (request, response) => {
    const body = signupBodySchema.safeParse(request.body);
    if (!body.success) {
      throw new ApiError(400, "INVALID_REQUEST", "Email and phone number are required");
    }
    const result = await signup.start(body.data.email, body.data.phoneNumber);
    response.status(201).json({
      success: true,
      data: result,
    });
  };

  return {
    start,
    verifyEmail: verificationHandler(signup, "email"),
    verifyPhone: verificationHandler(signup, "phone"),
    resendEmail: resendHandler(signup, "email"),
    resendPhone: resendHandler(signup, "phone"),
  };
}

export function createRefreshController(refresh: RefreshTokenRefresher): RequestHandler {
  return async (request, response) => {
    const body = refreshBodySchema.safeParse(request.body);
    if (!body.success) {
      throw new ApiError(400, "INVALID_REFRESH_TOKEN", "A valid refresh token is required");
    }

    const tokens = await refresh.refresh(body.data.refreshToken);
    response.status(200).json({
      success: true,
      data: { tokens },
    });
  };
}
