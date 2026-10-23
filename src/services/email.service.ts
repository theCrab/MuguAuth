import sgMail, { type MailDataRequired, type MailService } from "@sendgrid/mail";
import { OtpDeliveryError } from "./otp-delivery.error.js";

export interface EmailSender {
  sendVerificationCode(email: string, code: string): Promise<void>;
}

type SendGridClient = Pick<MailService, "send"> & Pick<MailService, "setApiKey">;

export class SendGridEmailService implements EmailSender {
  constructor(
    apiKey: string,
    private readonly fromEmail: string,
    private readonly client: SendGridClient = sgMail,
  ) {
    this.client.setApiKey(apiKey);
  }

  async sendVerificationCode(email: string, code: string): Promise<void> {
    const message: MailDataRequired = {
      to: email,
      from: this.fromEmail,
      subject: "Your MuguAuth verification code",
      text: `Your verification code is ${code}. It expires in 5 minutes.`,
    };

    try {
      await this.client.send(message);
    } catch {
      throw new OtpDeliveryError("email");
    }
  }
}
