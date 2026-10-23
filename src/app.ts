import express, { type ErrorRequestHandler } from "express";
import type { Router } from "express";
import { ApiError } from "./services/api.error.js";

export function createApp(
  authRouter?: Router,
  jwksRouter?: Router,
  protectedRouter?: Router,
) {
  const app = express();

  app.use(express.json({ limit: "16kb" }));
  if (authRouter) app.use("/auth", authRouter);
  if (jwksRouter) app.use(jwksRouter);
  if (protectedRouter) app.use(protectedRouter);

  app.use((_request, response) => {
    response.status(404).json({
      success: false,
      error: {
        message: "Resource not found",
        code: "NOT_FOUND",
      },
    });
  });

  const errorHandler: ErrorRequestHandler = (error, _request, response, _next) => {
    if (error instanceof ApiError) {
      response.status(error.status).json({
        success: false,
        error: {
          message: error.message,
          code: error.code,
        },
      });
      return;
    }

    if (error instanceof SyntaxError && "status" in error && error.status === 400) {
      response.status(400).json({
        success: false,
        error: {
          message: "Request body contains invalid JSON",
          code: "INVALID_JSON",
        },
      });
      return;
    }

    console.error(error);
    response.status(500).json({
      success: false,
      error: {
        message: "An unexpected error occurred",
        code: "INTERNAL_SERVER_ERROR",
      },
    });
  };

  app.use(errorHandler);
  return app;
}

export default createApp();
