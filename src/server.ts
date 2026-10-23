import "dotenv/config";
import { Redis } from "ioredis";
import { createDatabasePool } from "./config/database.js";
import { loadConfig } from "./config/env.js";
import { createApp } from "./app.js";
import { UserModel } from "./models/user.model.js";
import { createAuthRouter } from "./routes/auth.routes.js";
import { createJwksRouter } from "./routes/jwks.routes.js";
import { createProtectedRouter } from "./routes/protected.routes.js";
import { createAuthMiddleware } from "./middlewares/auth.middleware.js";
import { AuthTokenService } from "./services/auth-token.service.js";
import { SendGridEmailService } from "./services/email.service.js";
import { JwksService } from "./services/jwks.service.js";
import { OtpService } from "./services/otp.service.js";
import { RefreshTokenStore } from "./services/refresh-token.store.js";
import { RefreshService } from "./services/refresh.service.js";
import { RegistrationStore } from "./services/registration.store.js";
import { SignupService } from "./services/signup.service.js";
import { TwilioSmsService } from "./services/sms.service.js";

const config = loadConfig();
const redis = new Redis(config.REDIS_URL);
const database = createDatabasePool(config.DATABASE_URL);
const registrations = new RegistrationStore(redis);
const otp = new OtpService(registrations, config.OTP_HMAC_SECRET);
const refreshTokens = new RefreshTokenStore(redis);
const tokens = new AuthTokenService(refreshTokens, config);
const users = new UserModel(database);
const refresh = new RefreshService(refreshTokens, tokens, users);
const jwksService = new JwksService(config);
const signup = new SignupService(
  registrations,
  otp,
  new SendGridEmailService(config.SENDGRID_API_KEY, config.SENDGRID_FROM_EMAIL),
  new TwilioSmsService(
    config.TWILIO_ACCOUNT_SID,
    config.TWILIO_AUTH_TOKEN,
    config.TWILIO_FROM_NUMBER,
  ),
  users,
  tokens,
);
const app = createApp(
  createAuthRouter(signup, refresh),
  createJwksRouter(jwksService),
  createProtectedRouter(createAuthMiddleware(users, jwksService, config)),
);

app.listen(config.PORT, () => {
  console.log(`MuguAuth listening on port ${config.PORT}`);
});
