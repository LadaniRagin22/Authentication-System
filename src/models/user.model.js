import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
    tokenVersion: {
      type: Number,
      default: 0,
    },
  },
  {
    timestamps: true,
  }
);

userSchema.methods.comparePassword = async function (password) {
  const { createHash } = await import("node:crypto");
  const hashedPassword = createHash("sha256").update(password).digest("hex");
  return this.password === hashedPassword;
};

const User = mongoose.model("User", userSchema);

export default User;
