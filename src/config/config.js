import dotenv from "dotenv";

dotenv.config();

const config = {
  mongoURI: process.env.MONGO_URI || process.env.MONgo_URI || "mongodb://127.0.0.1:27017/authentication-system",
  JWT_SECRET: process.env.JWT_SECRET || "dev_secret_key",
};

export default config;