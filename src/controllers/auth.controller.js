import Usermodel from "../models/user.model.js";
import { createHash } from "node:crypto";
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import SessionModel from "../models/session.model.js";

export async function register(req, res) {
  try {
    const { username, email, password } = req.body || {};

    if (!username || !email || !password) {
      return res.status(400).json({ message: "Username, email, and password are required" });
    }

    const isAlreadyExist = await Usermodel.findOne({
      $or: [{ username }, { email }],
    });

    if (isAlreadyExist) {
      return res.status(409).json({ message: "User already exists" });
    }

    const hashedPassword = createHash("sha256").update(password).digest("hex");

    const user = await new Usermodel({
      username,
      email,
      password: hashedPassword,
    }).save();

    const accessToken = jwt.sign(
      { id: user._id, tokenVersion: user.tokenVersion || 0 },
      config.JWT_SECRET,
      { expiresIn: "15m" }
    );

    const refreshToken = jwt.sign(
      { id: user._id, tokenVersion: user.tokenVersion || 0 },
      config.JWT_SECRET,
      { expiresIn: "7d" }
    );

    const refreshTokenHash = createHash("sha256").update(refreshToken).digest("hex");

    await SessionModel.create({
      userId: user._id,
      refreshTokenHash,
      ip: req.ip,
      userAgent: req.get("User-Agent"),
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    return res.status(201).json({
      message: "User registered successfully",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
      token: accessToken,
      accessToken,
      refreshToken,
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
}

export async function login(req, res) {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const user = await Usermodel.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isPasswordValid = await user.comparePassword(password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const accessToken = jwt.sign(
      { id: user._id, tokenVersion: user.tokenVersion || 0 },
      config.JWT_SECRET,
      { expiresIn: "15m" }
    );

    const refreshToken = jwt.sign(
      { id: user._id, tokenVersion: user.tokenVersion || 0 },
      config.JWT_SECRET,
      { expiresIn: "7d" }
    );

    const refreshTokenHash = createHash("sha256").update(refreshToken).digest("hex");

    await SessionModel.create({
      userId: user._id,
      refreshTokenHash,
      ip: req.ip,
      userAgent: req.get("User-Agent"),
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    return res.status(200).json({
      message: "User logged in successfully",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
      token: accessToken,
      accessToken,
      refreshToken,
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
}

export async function getMe(req, res) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ message: "Token not provided" });
    }
    const token = authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : authHeader;

    if (!token) {
      return res.status(401).json({ message: "Token not provided" });
    }

    const decoded = jwt.verify(token, config.JWT_SECRET);
    if (typeof decoded === "string" || !decoded) {
      return res.status(401).json({ message: "Invalid token payload" });
    }
    const user = await Usermodel.findById(decoded.id).select("-password");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (decoded.tokenVersion !== undefined && decoded.tokenVersion !== user.tokenVersion) {
      return res.status(401).json({
        message: "Token has been invalidated (logged out all devices)",
      });
    }

    return res.status(200).json({
      _id: user._id,
      username: user.username,
      email: user.email,
      message: "User fetched successfully",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

export async function refreshToken(req, res) {
  try {
    const refreshToken =
      req.cookies?.refreshToken ||
      req.body.refreshToken ||
      req.headers["x-refresh-token"] ||
      (req.headers.authorization?.startsWith("Bearer ")
        ? req.headers.authorization.split(" ")[1]
        : req.headers.authorization);

    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh token not provided" });
    }

    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);
    if (typeof decoded === "string" || !decoded) {
      return res.status(401).json({ message: "Invalid token payload" });
    }

    const user = await Usermodel.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (decoded.tokenVersion !== undefined && decoded.tokenVersion !== user.tokenVersion) {
      return res.status(401).json({
        message: "Token has been invalidated (logged out all devices)",
      });
    }

    const refreshTokenHash = createHash("sha256").update(refreshToken).digest("hex");

    const session = await SessionModel.findOne({
      refreshTokenHash,
      revoked: false,
    });

    if (!session) {
      return res.status(401).json({ message: "Invalid or revoked refresh token" });
    }

    const newAccessToken = jwt.sign(
      { id: user._id, tokenVersion: user.tokenVersion || 0 },
      config.JWT_SECRET,
      { expiresIn: "15m" }
    );

    const newRefreshToken = jwt.sign(
      { id: user._id, tokenVersion: user.tokenVersion || 0 },
      config.JWT_SECRET,
      { expiresIn: "7d" }
    );

    const newRefreshTokenHash = createHash("sha256").update(newRefreshToken).digest("hex");

    session.refreshTokenHash = newRefreshTokenHash;
    await session.save();

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    return res.status(200).json({
      message: "Access token refreshed successfully",
      token: newAccessToken,
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired refresh token" });
  }
}

export async function logout(req, res) {
  try {
    const refreshToken =
      req.cookies?.refreshToken ||
      req.body.refreshToken ||
      req.headers["x-refresh-token"] ||
      (req.headers.authorization?.startsWith("Bearer ")
        ? req.headers.authorization.split(" ")[1]
        : req.headers.authorization);

    if (!refreshToken) {
      return res.status(400).json({ message: "Refresh token not provided" });
    }

    const refreshTokenHash = createHash("sha256").update(refreshToken).digest("hex");

    const session = await SessionModel.findOne({
      refreshTokenHash,
      revoked: false,
    });

    if (session) {
      session.revoked = true;
      await session.save();
    }

    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    return res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
}

export async function logoutAll(req, res) {
  try {
    const refreshToken =
      req.cookies?.refreshToken ||
      req.body.refreshToken ||
      req.headers["x-refresh-token"] ||
      (req.headers.authorization?.startsWith("Bearer ")
        ? req.headers.authorization.split(" ")[1]
        : req.headers.authorization);

    if (!refreshToken) {
      return res.status(400).json({ message: "Refresh token not provided" });
    }

    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);
    if (typeof decoded === "string" || !decoded) {
      return res.status(401).json({ message: "Invalid token payload" });
    }

    await SessionModel.updateMany(
      { userId: decoded.id, revoked: false },
      { revoked: true }
    );

    const user = await Usermodel.findById(decoded.id);
    if (user) {
      user.tokenVersion = (user.tokenVersion || 0) + 1;
      await user.save();
    }

    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    return res.status(200).json({ message: "Logged out from all devices successfully" });
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}