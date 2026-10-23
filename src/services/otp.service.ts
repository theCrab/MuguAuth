import { createHmac, randomInt } from "node:crypto";
import {
  type ChallengeIssueResult,
  type ChallengeVerificationResult,
  type VerificationChannel,
  RegistrationStore,
} from "./registration.store.js";

export const OTP_TTL_MS = 5 * 60 * 1000;
export const OTP_MAX_ATTEMPTS = 5;
export const OTP_RESEND_COOLDOWN_MS = 30 * 1000;
export const OTP_MAX_SENDS_PER_CHANNEL = 3;

export class OtpService {
  constructor(
    private readonly registrations: RegistrationStore,
    private readonly hmacSecret: string,
  ) {
    if (Buffer.byteLength(hmacSecret) < 32) {
      throw new Error("OTP HMAC secret must be at least 32 bytes");
    }
  }

  async issue(
    registrationId: string,
    channel: VerificationChannel,
    now = Date.now(),
  ): Promise<{ result: ChallengeIssueResult; code?: string }> {
    const code = randomInt(0, 1_000_000).toString().padStart(6, "0");
    const result = await this.registrations.issueChallenge(
      registrationId,
      channel,
      this.digest(registrationId, channel, code),
      now,
      {
        challengeTtlMs: OTP_TTL_MS,
        cooldownMs: OTP_RESEND_COOLDOWN_MS,
        maxSends: OTP_MAX_SENDS_PER_CHANNEL,
      },
    );

    return result === "issued" ? { result, code } : { result };
  }

  async verify(
    registrationId: string,
    channel: VerificationChannel,
    code: string,
    now = Date.now(),
  ): Promise<ChallengeVerificationResult> {
    if (!/^\d{6}$/.test(code)) return "invalid";
    return this.registrations.verifyChallenge(
      registrationId,
      channel,
      this.digest(registrationId, channel, code),
      now,
      OTP_MAX_ATTEMPTS,
    );
  }

  async clear(registrationId: string, channel: VerificationChannel): Promise<boolean> {
    return this.registrations.clearChallenge(registrationId, channel);
  }

  private digest(registrationId: string, channel: VerificationChannel, code: string): string {
    return createHmac("sha256", this.hmacSecret)
      .update(`${registrationId}:${channel}:${code}`)
      .digest("hex");
  }
}
