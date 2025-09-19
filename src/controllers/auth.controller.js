import logger from "#src/config/logger.js";
import { authenticateUser, createUser } from "#src/services/auth.service.js";
import { cookies } from "#src/utils/cookies.js";
import { formatValidationError } from "#src/utils/format.js";
import { jwtToken } from "#src/utils/jwt.js";
import {
  signInSchema,
  signupSchema,
} from "#src/validations/auth.validation.js";

export const signUp = async (req, res, next) => {
  try {
    const validationResult = signupSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: "Validation failed",
        details: formatValidationError(validationResult.error),
      });
    }

    const { email, name, password, role } = validationResult.data;

    const user = await createUser({ name, email, password, role });

    const token = jwtToken.sign({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    });

    cookies.set(res, "token", token);

    logger.info(`User registered successfully: ${email}`);
    res.status(201).json({
      message: "User registered",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (e) {
    logger.error("Signup Error", e);

    if (e.message === "User with this email already exists") {
      return res.status(400).json({
        error: "Email alredy exist",
      });
    }

    next(e);
  }
};

export const signIn = async (req, res, next) => {
  try {
    const validationResult = signInSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: "validation failed",
        details: formatValidationError(validationResult.error),
      });
    }

    const { email, password } = validationResult.data;

    const user = await authenticateUser({ email, password });

    const token = jwtToken.sign({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    });

    cookies.set(res, "token", token);

    logger.info(`User signed in successfully: ${email}`);
    res.status(200).json({
      message: "User signed in",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (e) {
    logger.error("Sign in error:", e);

    if (e.message === "User not found" || e.message === "Invalid password") {
      return res.status(401).json({
        error: "Invalid credentials",
      });
    }

    next(e);
  }
};

export const signOut = async (req, res, next) => {
  try {
    cookies.clear(res, "token");

    logger.info("User signed out successfully");
    res.status(200).json({
      message: "User signed out successfully",
    });
  } catch (e) {
    logger.error("Sign out error", e);

    next(e);
  }
};
