// src/server.js
import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import session from "express-session";
import passport from "passport";

import { initSamlStrategy } from "./services/saml.js"; // ✅ ensure this exists/exported

// Routes
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

console.log("ENV CHECK:", {
  NODE_ENV: process.env.NODE_ENV,
  PORT: process.env.PORT,
  SAML_CALLBACK_URL: process.env.SAML_CALLBACK_URL,
  SAML_ISSUER: process.env.SAML_ISSUER,
  OKTA_SIGNON_URL: process.env.OKTA_SIGNON_URL,
  OKTA_METADATA_URL: process.env.OKTA_METADATA_URL ? "[set]" : "[missing]",
  OKTA_X509_CERT_PEM: process.env.OKTA_X509_CERT_PEM ? "[set]" : "[missing]",
  OKTA_X509_CERT_B64: process.env.OKTA_X509_CERT_B64 ? "[set]" : "[missing]",
  CORS_ORIGIN: process.env.CORS_ORIGIN,
  FRONTEND_BASE_URL: process.env.FRONTEND_BASE_URL,
});

app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

// Okta SAML posts application/x-www-form-urlencoded
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));

/** ============================
 *  Session (Cookie)
 *  ============================ */
app.use(
  session({
    name: "eandi.sid",
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      httpOnly: true,
      secure: isProd, // required for SameSite=None
      sameSite: isProd ? "none" : "lax",
      maxAge: 8 * 60 * 60 * 1000,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

/** ============================
 *  Initialize SAML Strategy
 *  MUST be before /api/auth routes
 *  ============================ */
try {
  await initSamlStrategy();
  console.log("🧩 [SAML INIT] STRATEGY REGISTERED", {
    strategies: Object.keys(passport?._strategies || {}),
  });
} catch (e) {
  console.error("❌ SAML init failed at startup:", e?.message || e);
  throw e; // fail fast
}

/** ============================
 *  CORS
 *  ============================ */
const allowedOrigins = new Set(
  (process.env.CORS_ORIGIN || "")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean)
);

if (process.env.FRONTEND_BASE_URL) {
  try {
    allowedOrigins.add(new URL(process.env.FRONTEND_BASE_URL).origin);
  } catch (e) {
    console.warn(
      "⚠️ FRONTEND_BASE_URL is not a valid URL:",
      process.env.FRONTEND_BASE_URL
    );
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

app.use(
  cors((req, cb) => {
    const origin = req.header("Origin");

    // No Origin header (server-to-server, health checks, etc.)
    if (!origin) {
      return cb(null, {
        origin: true,
        credentials: true,
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
      });
    }

    // Allow Okta / SAML endpoints broadly (Okta posts from okta.com)
    if (req.path.startsWith("/api/auth/saml")) {
      return cb(null, {
        origin: true,
        credentials: true,
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
      });
    }

    // Some browser flows can send Origin: null
    if (origin === "null") {
      return cb(null, {
        origin: !isProd,
        credentials: true,
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
      });
    }

    // Normal UI/API calls
    if (allowedOrigins.has(origin) || isOktaOrigin(origin)) {
      return cb(null, {
        origin: true,
        credentials: true,
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], // ✅ FIXED
        allowedHeaders: ["Content-Type", "Authorization"],
      });
    }

    console.warn("❌ CORS blocked:", { origin, path: req.path });
    return cb(new Error(`Not allowed by CORS: ${origin}`), { origin: false });
  })
);

// Preflight
app.options("*", cors({ origin: true, credentials: true }));

/** ============================
 *  Logging
 *  ============================ */
app.use(morgan("dev"));

/** ============================
 *  Routes
 *  ============================ */
app.get("/", (_req, res) => res.status(200).send("ENI SSP Backend is running"));

app.get("/api/health", (_req, res) =>
  res.status(200).json({ status: "ok", time: new Date().toISOString() })
);

app.use("/api", health);
app.use("/api/auth", auth);
app.use("/api/auth", sqlAuthRoutes);
app.use("/api/users", users);
app.use("/api/uploads", uploads);
app.use("/api", reports);
app.use("/api", sspReportsRoutes);
app.use("/api/notify-accounting", notifyAccounting);
app.use("/api", me);

// 404
app.use((_req, res) => res.status(404).json({ error: "Not found" }));

// Error handler
app.use((err, _req, res, _next) => {
  console.error("❌ API Error:", err.message);
  res.status(err.status || 500).json({ error: err.message });
});

const port = Number(process.env.PORT) || 8080;
app.listen(port, () => console.log(`✅ API listening on :${port}`));
