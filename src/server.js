// src/server.js
import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import session from "express-session";
import passport from "passport";

/**
 * Register SAML strategy
 * - If saml.js is self-initializing, import is enough ✅
 * - If saml.js exports initPassport(), you MUST call it (see commented block below)
 */
import "./services/saml.js";
// If you ever switch to initPassport style, use this instead:
// import { initPassport } from "./services/saml.js";

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

/* ------------------------------------------------------
   Startup banner + ENV CHECK (avoid secrets)
------------------------------------------------------ */
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
  OKTA_X509_CERT_B64: process.env.OKTA_X509_CERT_B64 ? "[set]" : "[missing]",
  CORS_ORIGIN: process.env.CORS_ORIGIN,
  FRONTEND_BASE_URL: process.env.FRONTEND_BASE_URL,
});

/* ------------------------------------------------------
   Security headers
------------------------------------------------------ */
app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

/* ------------------------------------------------------
   Body parsing
   IMPORTANT: Okta POSTs form-encoded SAMLResponse.
   You already have urlencoded enabled ✅
------------------------------------------------------ */
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));

/* ------------------------------------------------------
   ✅ Extra request logging for SAML endpoints (SAFE)
------------------------------------------------------ */
const DEBUG_SAML =
  String(process.env.DEBUG_SAML || "true").toLowerCase() === "true";
app.use((req, _res, next) => {
  if (!DEBUG_SAML) return next();

  // Only log auth/saml traffic to avoid noisy logs
  if (req.path.startsWith("/api/auth/saml")) {
    console.log("🧩 [SAML REQ]", {
      method: req.method,
      path: req.path,
      host: req.get("host"),
      origin: req.get("origin"),
      contentType: req.get("content-type"),
      hasCookie: !!req.get("cookie"),
      bodyKeys: Object.keys(req.body || {}),
      // Do NOT log SAMLResponse value itself
      hasSamlResponse: !!req.body?.SAMLResponse,
      relayState: req.body?.RelayState ? "[present]" : "[missing]",
      xfProto: req.get("x-forwarded-proto"),
      xfHost: req.get("x-forwarded-host"),
      xfFor: req.get("x-forwarded-for"),
    });
  }
  next();
});

/* ------------------------------------------------------
   ✅ Session BEFORE passport
------------------------------------------------------ */
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
   ✅ CORS (your original)
====================================================== */

const allowedOrigins = new Set(
  (process.env.CORS_ORIGIN || "")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean)
);

if (process.env.FRONTEND_BASE_URL) {
  try {
    allowedOrigins.add(new URL(process.env.FRONTEND_BASE_URL).origin);
  } catch {
    // ignore
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

    if (!origin) {
      return cb(null, {
        origin: true,
        credentials: true,
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
      });
    }

    // ✅ Never block SAML endpoints
    if (req.path.startsWith("/api/auth/saml")) {
      return cb(null, {
        origin: true,
        credentials: true,
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
      });
    }

    if (origin === "null") {
      return cb(null, {
        origin: !isProd,
        credentials: true,
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
      });
    }

    if (allowedOrigins.has(origin) || isOktaOrigin(origin)) {
      return cb(null, {
        origin: true,
        credentials: true,
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
      });
    }

    return cb(new Error(`Not allowed by CORS: ${origin}`), { origin: false });
  })
);

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

/* 404 */
app.use((_req, res) => res.status(404).json({ error: "Not found" }));

/* Error handler */
app.use((err, _req, res, _next) => {
  console.error("❌ API Error:", err.message);
  res.status(err.status || 500).json({ error: err.message });
});

/* Start */
const port = Number(process.env.PORT) || 8080;

// If you switch to initPassport style, do this:
// (async () => {
//   await initPassport();
//   app.listen(port, () => console.log(`✅ API listening on :${port}`));
// })();

app.listen(port, () => console.log(`✅ API listening on :${port}`));
