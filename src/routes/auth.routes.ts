import { Router } from "express";
import { createAuthController, createRefreshController } from "../controllers/auth.controller.js";
import type { RefreshTokenRefresher } from "../services/refresh.service.js";
import { SignupService } from "../services/signup.service.js";

export function createAuthRouter(
  signup: SignupService,
  refresh: RefreshTokenRefresher,
): Router {
  const router = Router();
  const controller = createAuthController(signup);

  router.post("/signup", controller.start);
  router.post("/signup/:registrationId/verify/email", controller.verifyEmail);
  router.post("/signup/:registrationId/verify/phone", controller.verifyPhone);
  router.post("/signup/:registrationId/resend/email", controller.resendEmail);
  router.post("/signup/:registrationId/resend/phone", controller.resendPhone);
  router.post("/refresh", createRefreshController(refresh));

  return router;
}
