import express from "express";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import authrouter from "./routes/auth.routes.js";

const app = express(); 


app.use(express.json());
app.use(cookieParser());
app.use(morgan("dev")); //middleware to parse incoming JSON requests

app.use("/api/auth", authrouter);

export default app;