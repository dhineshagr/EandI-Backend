// src/server.js
import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import session from "express-session";
import passport from "passport";

/* Register SAML strategy */
import "./services/saml.js";

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

/* ✅ Azure reverse proxy */
app.set("trust proxy", 1);

const isProd =
  String(process.env.NODE_ENV || "").toLowerCase() === "production";

/* ENV CHECK (avoid secrets) */
console.log("ENV CHECK:", {
  NODE_ENV: process.env.NODE_ENV,
  PORT: process.env.PORT,
  SAML_CALLBACK_URL: process.env.SAML_CALLBACK_URL,
  SAML_ISSUER: process.env.SAML_ISSUER,
  OKTA_SIGNON_URL: process.env.OKTA_SIGNON_URL,
  CORS_ORIGIN: process.env.CORS_ORIGIN,
  FRONTEND_BASE_URL: process.env.FRONTEND_BASE_URL,
});

/* Security headers */
app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

/* Body parsing */
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));

/* ✅ Session BEFORE passport */
app.use(
  session({
    name: "eandi.sid",
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      httpOnly: true,
      secure: isProd, // ✅ true in Azure
      sameSite: isProd ? "none" : "lax", // ✅ cross-site cookies for SAML in prod
      maxAge: 8 * 60 * 60 * 1000,
    },
  })
);

/* Passport */
app.use(passport.initialize());
app.use(passport.session());

/* ✅ CORS */
const allowedOrigins = (process.env.CORS_ORIGIN || "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

if (!allowedOrigins.length && !isProd) {
  allowedOrigins.push("http://localhost:5173");
}

app.use(
  cors({
    origin(origin, cb) {
      // server-to-server
      if (!origin) return cb(null, true);

      // browsers sometimes send Origin: "null"
      if (origin === "null") {
        if (!isProd) return cb(null, true);
        return cb(new Error("Not allowed by CORS: null"), false);
      }

      if (allowedOrigins.includes(origin)) return cb(null, true);

      return cb(new Error(`Not allowed by CORS: ${origin}`), false);
    },
    credentials: true,
  })
);

app.options("*", cors());

/* Logging */
app.use(morgan("dev"));

/* Health + root BEFORE 404 */
app.get("/", (_req, res) => res.status(200).send("ENI SSP Backend is running"));

app.get("/api/health", (_req, res) => {
  res.status(200).json({ status: "ok", time: new Date().toISOString() });
});

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

/* 404 */
app.use((_req, res) => res.status(404).json({ error: "Not found" }));

/* Error handler */
app.use((err, _req, res, _next) => {
  console.error("❌ API Error:", err.message);
  res.status(err.status || 500).json({ error: err.message });
});

/* Start */
const port = Number(process.env.PORT) || 8080;
app.listen(port, () => console.log(`✅ API listening on :${port}`));
