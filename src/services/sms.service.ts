import twilio, { type Twilio } from "twilio";
import { OtpDeliveryError } from "./otp-delivery.error.js";

export interface SmsSender {
  sendVerificationCode(phoneNumber: string, code: string): Promise<void>;
}

type TwilioClient = Pick<Twilio, "messages">;

export class TwilioSmsService implements SmsSender {
  private readonly client: TwilioClient;

  constructor(
    accountSid: string,
    authToken: string,
    private readonly fromNumber: string,
    client?: TwilioClient,
  ) {
    this.client = client ?? twilio(accountSid, authToken);
  }

  async sendVerificationCode(phoneNumber: string, code: string): Promise<void> {
    try {
      await this.client.messages.create({
        from: this.fromNumber,
        to: phoneNumber,
        body: `Your MuguAuth verification code is ${code}. It expires in 5 minutes.`,
      });
    } catch {
      throw new OtpDeliveryError("phone");
    }
  }
}
