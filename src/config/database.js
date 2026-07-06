import mongoose from "mongoose";
import config from "./config.js";



async function connectDB() {
  try {
    await mongoose.connect(config.mongoURI);
    console.log("MongoDB connected successfully");
  } catch (error) {
    console.warn("MongoDB connection failed:", error.message);
    console.warn("Continuing without database connection");
  }
}

export default connectDB;