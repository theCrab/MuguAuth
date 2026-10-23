import { Router } from "express";
import type { RequestHandler } from "express";
import { ApiError } from "../services/api.error.js";

export function createProtectedRouter(authenticate: RequestHandler): Router {
  const router = Router();

  router.get("/auth/me", authenticate, (request, response) => {
    const user = request.authenticatedUser;
    if (!user) {
      throw new ApiError(401, "AUTHENTICATION_REQUIRED", "A valid access token is required");
    }

    response.status(200).json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          phoneNumber: user.phone_number,
          isActive: user.is_active,
        },
      },
    });
  });

  return router;
}
