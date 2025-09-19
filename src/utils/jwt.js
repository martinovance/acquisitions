import logger from "#src/config/logger.js";
import jwt from "jsonwebtoken";

const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-please-change-in-production";
const JWT_EXPIRE_IN = "1d";

export const jwtToken = {
  sign: payload => {
    try {
      return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRE_IN });
    } catch (error) {
      logger.error("Failed to authenticate token", error);
      throw new Error("Filed to authenticate token");
    }
  },
  verify: token => {
    try {
      return jwt.verify(token, JWT_SECRET);
    } catch (error) {
      logger.error("Failed to authenticate token", error);
      throw new Error("Filed to authenticate token");
    }
  },
};
