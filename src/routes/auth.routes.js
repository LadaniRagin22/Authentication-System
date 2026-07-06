import { Router } from "express";
import * as authController from "../controllers/auth.controller.js";

const authrouter = Router();

/**
 * POST /api/auth/register
 */
authrouter.post("/register", authController.register);

/**
 * POST /api/auth/login
 */
authrouter.post("/login", authController.login);

/**
 * POST /api/auth/refresh-token
 */
authrouter.post("/refresh-token", authController.refreshToken);

/**
 * GET /api/auth/me
 */
authrouter.get("/me", authController.getMe);

/**
 * GET /api/auth/get-me
 */
authrouter.get("/get-me", authController.getMe);

/**
 * GET /api/auth/getMe
 */
authrouter.get("/getMe", authController.getMe);

/**
 * ALL /api/auth/logout
 */
authrouter.all("/logout", authController.logout);

/**
 * ALL /api/auth/logout-all
 */
authrouter.all("/logout-all", authController.logoutAll);

/**
 * ALL /api/auth/logoutAll
 */
authrouter.all("/logoutAll", authController.logoutAll);

export default authrouter;