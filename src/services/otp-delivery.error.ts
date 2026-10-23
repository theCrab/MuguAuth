import { ApiError } from "./api.error.js";

export class OtpDeliveryError extends ApiError {
  constructor(channel: "email" | "phone" | "signup") {
    super(
      503,
      "OTP_DELIVERY_FAILED",
      channel === "signup"
        ? "Unable to deliver signup verification codes"
        : `Unable to deliver ${channel} verification code`,
    );
    this.name = "OtpDeliveryError";
  }
}
