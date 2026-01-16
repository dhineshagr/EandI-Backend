// src/routes/auth.js
import { Router } from "express";
import passport from "passport";

const router = Router();
const FRONTEND_URL =
  process.env.FRONTEND_BASE_URL ||
  process.env.FRONTEND_URL ||
  "http://localhost:5173";

// Turn on while debugging SAML callback issues
const DEBUG_SAML = true;

function samlDbg(label, obj) {
  if (!DEBUG_SAML) return;
  console.log(`🧩 [SAML DEBUG] ${label}`, obj);
}

/**
 * Start SAML Login
 * GET /api/auth/saml/login
 */
router.get("/saml/login", (req, res, next) => {
  samlDbg("START LOGIN", {
    url: req.originalUrl,
    host: req.get("host"),
    origin: req.get("origin"),
  });

  return passport.authenticate("saml")(req, res, next);
});

/**
 * ✅ OPTION B FIX
 * Okta is POSTing SAMLResponse to /api/auth/saml/login (not /callback)
 * So we accept POST here and treat it exactly like the callback.
 *
 * POST /api/auth/saml/login
 */
router.post("/saml/login", (req, res, next) => {
  samlDbg("POSTED TO /saml/login (alias to callback)", {
    url: req.originalUrl,
    host: req.get("host"),
    origin: req.get("origin"),
    bodyKeys: Object.keys(req.body || {}),
  });

  return passport.authenticate("saml", (err, user, info) => {
    if (err || !user) {
      console.error("❌ SAML CALLBACK FAILED", {
        err: err?.message || err,
        info,
      });
      return res.redirect(`${FRONTEND_URL}/login?error=saml_failed`);
    }

    // ✅ VERY IMPORTANT: create passport session
    req.login(user, (loginErr) => {
      if (loginErr) {
        console.error("❌ req.login() failed:", loginErr);
        return res.redirect(`${FRONTEND_URL}/login?error=session_failed`);
      }

      // ✅ store flat user for your middleware
      req.session.user = user;

      samlDbg("SAML SUCCESS (session stored)", {
        email: user.email,
        name: user.name,
        hasSession: !!req.session,
      });

      return res.redirect(`${FRONTEND_URL}/upload`);
    });
  })(req, res, next);
});

/**
 * (Optional) keep the real callback endpoint too
 * POST /api/auth/saml/callback
 */
router.post("/saml/callback", (req, res, next) => {
  samlDbg("CALLBACK HIT (/saml/callback)", {
    url: req.originalUrl,
    host: req.get("host"),
    origin: req.get("origin"),
    bodyKeys: Object.keys(req.body || {}),
  });

  return passport.authenticate("saml", (err, user, info) => {
    if (err || !user) {
      console.error("❌ SAML CALLBACK FAILED", {
        err: err?.message || err,
        info,
      });
      return res.redirect(`${FRONTEND_URL}/login?error=saml_failed`);
    }

    req.login(user, (loginErr) => {
      if (loginErr) {
        console.error("❌ req.login() failed:", loginErr);
        return res.redirect(`${FRONTEND_URL}/login?error=session_failed`);
      }

      req.session.user = user;

      samlDbg("SAML SUCCESS (session stored)", {
        email: user.email,
        name: user.name,
        hasSession: !!req.session,
      });

      return res.redirect(`${FRONTEND_URL}/upload`);
    });
  })(req, res, next);
});

export default router;
