import { Router } from "express";
import { JwksService } from "../services/jwks.service.js";

export function createJwksRouter(jwks: JwksService): Router {
  const router = Router();

  router.get("/.well-known/jwks.json", async (_request, response) => {
    const keySet = await jwks.getKeySet();
    response
      .set("Cache-Control", "public, max-age=300, must-revalidate")
      .json(keySet);
  });

  return router;
}
