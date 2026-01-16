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
      secure: isProd, // ✅ true in Azure (HTTPS)
      sameSite: isProd ? "none" : "lax", // ✅ cross-site cookies for SAML in prod
      maxAge: 8 * 60 * 60 * 1000,
    },
  })
);

/* Passport */
app.use(passport.initialize());
app.use(passport.session());

/* ======================================================
   ✅ CORS (FIXED for Okta tile + SAML)
   - Allows your frontend origins from CORS_ORIGIN
   - Allows *.okta.com / *.oktapreview.com
   - ✅ Never blocks /api/auth/saml/* (Okta tile hits these with Origin header)
====================================================== */

const allowedOrigins = new Set(
  (process.env.CORS_ORIGIN || "")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean)
);

// Optional: also allow FRONTEND_BASE_URL origin (if set)
if (process.env.FRONTEND_BASE_URL) {
  try {
    allowedOrigins.add(new URL(process.env.FRONTEND_BASE_URL).origin);
  } catch {
    // ignore bad url
  }
}

if (!isProd) {
  allowedOrigins.add("http://localhost:5173");
  allowedOrigins.add("http://localhost:3001");
}

function isOktaOrigin(origin) {
  try {
    const { hostname } = new URL(origin);
    return (
      hostname.endsWith(".okta.com") || hostname.endsWith(".oktapreview.com")
    );
  } catch {
    return false;
  }
}

// Request-aware CORS delegate (lets us bypass SAML endpoints)
app.use(
  cors((req, cb) => {
    const origin = req.header("Origin");

    // Server-to-server / top-level navigation (no Origin header)
    if (!origin) {
      return cb(null, {
        origin: true,
        credentials: true,
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
      });
    }

    // ✅ Never block SAML endpoints (Okta tile can send Origin: https://eandi.okta.com)
    // Note: req.path does NOT include query string.
    if (req.path.startsWith("/api/auth/saml")) {
      return cb(null, {
        origin: true,
        credentials: true,
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
      });
    }

    // browsers sometimes send Origin: "null"
    if (origin === "null") {
      return cb(null, {
        origin: !isProd,
        credentials: true,
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
      });
    }

    // Allow explicit allow-list OR Okta domains
    if (allowedOrigins.has(origin) || isOktaOrigin(origin)) {
      return cb(null, {
        origin: true,
        credentials: true,
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
      });
    }

    // Block everything else
    return cb(new Error(`Not allowed by CORS: ${origin}`), { origin: false });
  })
);

// ✅ IMPORTANT: preflight must use SAME cors delegate
app.options(
  "*",
  cors((req, cb) => {
    const origin = req.header("Origin");
    if (!origin) return cb(null, { origin: true, credentials: true });
    return cb(null, { origin: true, credentials: true });
  })
);

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

/* 404 error*/
app.use((_req, res) => res.status(404).json({ error: "Not found" }));

/* Error handler */
app.use((err, _req, res, _next) => {
  console.error("❌ API Error:", err.message);
  res.status(err.status || 500).json({ error: err.message });
});

/* Start */
const port = Number(process.env.PORT) || 8080;
app.listen(port, () => console.log(`✅ API listening on :${port}`));
