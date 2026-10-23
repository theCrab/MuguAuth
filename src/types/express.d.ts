import type { User } from "../models/user.model.js";

declare global {
  namespace Express {
    interface Request {
      authenticatedUser?: User;
    }
  }
}

export {};
