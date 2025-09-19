import logger from "#src/config/logger.js";
import bcrypt from "bcrypt";
import { db } from "#config/database.js";
import { users } from "#models/user.model.js";
import { eq } from "drizzle-orm";

export const hashPassword = async password => {
  try {
    return await bcrypt.hash(password, 10);
  } catch (e) {
    logger.error(`Error hashing the password: ${e}`);
    throw new Error("Error hashing");
  }
};

export const createUser = async ({ name, email, password, role = "user" }) => {
  try {
    const extistingUser = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (extistingUser.length > 0)
      throw new Error("User with this email already exist");

    const password_hash = await hashPassword(password);

    const [newUser] = await db
      .insert(users)
      .values({ name, email, password: password_hash, role })
      .returning({
        id: users.id,
        name: users.name,
        email: users.email,
        role: users.role,
        created_at: users.created_at,
      });

    logger.info(`User ${newUser.email} created successfully`);

    return newUser;
  } catch (e) {
    logger.error(`Error creating the user: ${e}`);
    throw e;
  }
};

export const comparePassword = async (password, hashedPassword) => {
  try {
    return await bcrypt.compare(password, hashedPassword);
  } catch (e) {
    logger.error(`Password do not match: ${e}`);
    throw new Error("Error comparing password");
  }
};

export const authenticateUser = async ({ email, password }) => {
  try {
    const [extistingUser] = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (!extistingUser) throw new Error("User not found");

    const isPasswordValid = await comparePassword(
      password,
      extistingUser.password
    );

    if (!isPasswordValid) {
      throw new Error("Invalid password");
    }

    logger.info(`User ${extistingUser.email} authenticated successfully`);
    return {
      id: extistingUser.id,
      name: extistingUser.name,
      email: extistingUser.email,
      role: extistingUser.role,
      created_at: extistingUser.created_at,
    };
  } catch (e) {
    logger.error(`Invalid credentials: ${e}`);
    throw new Error("Invalid credentials");
  }
};
