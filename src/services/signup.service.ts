import type { EmailSender } from "./email.service.js";
import { ApiError } from "./api.error.js";
import {
  type ChallengeVerificationResult,
  type VerificationChannel,
  RegistrationStore,
} from "./registration.store.js";
import { OtpService } from "./otp.service.js";
import { OtpDeliveryError } from "./otp-delivery.error.js";
import { normalizeRegistrationContacts } from "./registration.store.js";
import type { SmsSender } from "./sms.service.js";
import type { UserRepository } from "../models/user.model.js";
import type { AuthTokenIssuer, IssuedAuthTokens } from "./auth-token.service.js";

export interface SignupVerificationResult {
  result: ChallengeVerificationResult;
  tokens?: IssuedAuthTokens;
}

export class RegistrationFlowError extends ApiError {
  constructor(status: number, code: string, message: string) {
    super(status, code, message);
    this.name = "RegistrationFlowError";
  }
}

export class SignupService {
  constructor(
    private readonly registrations: RegistrationStore,
    private readonly otp: OtpService,
    private readonly emailSender: EmailSender,
    private readonly smsSender: SmsSender,
    private readonly users: UserRepository,
    private readonly tokens: AuthTokenIssuer,
  ) {}

  async start(emailInput: string, phoneInput: string): Promise<{ registrationId: string }> {
    const contacts = normalizeRegistrationContacts(emailInput, phoneInput);
    const registrationId = await this.registrations.create(contacts);

    const emailChallenge = await this.otp.issue(registrationId, "email");
    const phoneChallenge = await this.otp.issue(registrationId, "phone");
    if (!emailChallenge.code || !phoneChallenge.code) {
      const deleted = await this.registrations.delete(registrationId);
      if (!deleted) throw new Error("Unable to clear pending registration after challenge failure");
      throw new OtpDeliveryError("signup");
    }

    const deliveryResults = await Promise.allSettled([
      this.emailSender.sendVerificationCode(contacts.email, emailChallenge.code),
      this.smsSender.sendVerificationCode(contacts.phoneNumber, phoneChallenge.code),
    ]);
    if (deliveryResults.some((result) => result.status === "rejected")) {
      const deleted = await this.registrations.delete(registrationId);
      if (!deleted) throw new Error("Unable to clear pending registration after delivery failure");
      throw new OtpDeliveryError("signup");
    }

    return { registrationId };
  }

  async verify(
    registrationId: string,
    channel: VerificationChannel,
    code: string,
  ): Promise<SignupVerificationResult> {
    const result = await this.otp.verify(registrationId, channel, code);
    if (result !== "registration_complete" && result !== "already_verified") {
      return { result };
    }

    const registration = await this.registrations.get(registrationId);
    if (!registration) return { result: "expired" };
    if (!registration.emailVerified || !registration.phoneVerified) return { result };

    const user = await this.users.createOrGetByContacts({
      email: registration.email,
      phoneNumber: registration.phoneNumber,
    });
    if (result === "already_verified") return { result };
    if (!user.is_active) {
      throw new ApiError(403, "ACCOUNT_INACTIVE", "Account is inactive");
    }

    const tokens = await this.tokens.issueForUser(user.id);
    return { result, tokens };
  }

  async resend(registrationId: string, channel: VerificationChannel): Promise<void> {
    const registration = await this.registrations.get(registrationId);
    if (!registration) {
      throw new RegistrationFlowError(410, "REGISTRATION_EXPIRED", "Registration expired");
    }
    if (channel === "email" ? registration.emailVerified : registration.phoneVerified) {
      throw new RegistrationFlowError(409, "CHANNEL_ALREADY_VERIFIED", "Contact method is already verified");
    }

    const challenge = await this.otp.issue(registrationId, channel);
    if (!challenge.code) {
      if (challenge.result === "cooldown" || challenge.result === "send_limit") {
        throw new RegistrationFlowError(429, "OTP_RESEND_LIMIT", "Wait before requesting another code");
      }
      if (challenge.result === "already_verified") {
        throw new RegistrationFlowError(409, "CHANNEL_ALREADY_VERIFIED", "Contact method is already verified");
      }
      throw new RegistrationFlowError(410, "REGISTRATION_EXPIRED", "Registration expired");
    }

    try {
      if (channel === "email") {
        await this.emailSender.sendVerificationCode(registration.email, challenge.code);
      } else {
        await this.smsSender.sendVerificationCode(registration.phoneNumber, challenge.code);
      }
    } catch (error) {
      await this.otp.clear(registrationId, channel);
      if (error instanceof OtpDeliveryError) throw error;
      throw new OtpDeliveryError(channel);
    }
  }
}
