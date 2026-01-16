// src/server.js
import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import session from "express-session";
import passport from "passport";

import { initSamlStrategy } from "./services/saml.js"; // ✅ IMPORTANT

// ✅ Register strategy NOW (sync) - fail startup if broken
initSamlStrategy();

/* Routes */
import health from "./routes/health.js";
import auth from "./routes/auth.js";
import sqlAuthRoutes from "./routes/sqlAuth.js";
import users from "./routes/users.js";
import uploads from "./routes/uploads.js";
import reports from "./routes/reports.js";
import sspReportsRoutes from "./routes/sspreports.js";
import notifyAccounting from "./routes/notifyAccounting.js";
import me from "./routes/me.js";

const app = express();
app.set("trust proxy", 1);

const isProd =
  String(process.env.NODE_ENV || "").toLowerCase() === "production";

console.log("🚀 Server starting...", {
  node: process.version,
  env: process.env.NODE_ENV,
  isProd,
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    name: "eandi.sid",
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? "none" : "lax",
      maxAge: 8 * 60 * 60 * 1000,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.use(morgan("dev"));

/* Routes */
app.use("/api", health);
app.use("/api/auth", auth);
app.use("/api/auth", sqlAuthRoutes);
app.use("/api/users", users);
app.use("/api/uploads", uploads);
app.use("/api", reports);
app.use("/api", sspReportsRoutes);
app.use("/api/notify-accounting", notifyAccounting);
app.use("/api", me);

app.use((_req, res) => res.status(404).json({ error: "Not found" }));

app.use((err, _req, res, _next) => {
  console.error("❌ API Error:", err.message);
  res.status(err.status || 500).json({ error: err.message });
});

const port = Number(process.env.PORT) || 8080;
app.listen(port, () => console.log(`✅ API listening on :${port}`));
