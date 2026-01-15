// src/routes/auth.js
import { Router } from "express";
import passport from "passport";

const router = Router();

/**
 * ======================================================
 * ENV
 * ======================================================
 * Prefer these envs (set in Azure App Settings):
 *  - FRONTEND_BASE_URL            = https://<frontend>.azurewebsites.net
 *  - FRONTEND_SUCCESS_REDIRECT    = https://<frontend>.azurewebsites.net/upload   (or /)
 *
 * Backward compatibility:
 *  - FRONTEND_URL                 (older name)
 */
const FRONTEND_BASE_URL = (
  process.env.FRONTEND_BASE_URL ||
  process.env.FRONTEND_URL ||
  ""
)
  .trim()
  .replace(/\/+$/, "");

if (!FRONTEND_BASE_URL) {
  // fail fast (prevents accidental localhost redirects)
  throw new Error("Missing FRONTEND_BASE_URL (or FRONTEND_URL) env var");
}

const FRONTEND_SUCCESS_REDIRECT = (
  process.env.FRONTEND_SUCCESS_REDIRECT || `${FRONTEND_BASE_URL}/`
).trim();

const FRONTEND_LOGIN_REDIRECT = `${FRONTEND_BASE_URL}/login`;

// Turn on while debugging SAML callback issues
const DEBUG_SAML =
  String(process.env.DEBUG_SAML || "true").toLowerCase() === "true";

function samlDbg(label, obj) {
  if (!DEBUG_SAML) return;
  console.log(`🧩 [SAML DEBUG] ${label}`, obj);
}

/**
 * ======================================================
 * Shared SAML callback handler
 * ======================================================
 * Used by BOTH:
 *  - POST /api/auth/saml/callback   (correct ACS endpoint)
 *  - POST /api/auth/saml/login      (safety alias if Okta posts here)
 */
function handleSamlCallback(req, res, next) {
  passport.authenticate("saml", (err, user, info) => {
    if (err || !user) {
      console.error("❌ SAML CALLBACK FAILED", {
        err: err?.message || err,
        info,
      });

      samlDbg("CALLBACK REQUEST META", {
        method: req.method,
        url: req.originalUrl,
        origin: req.get("origin"),
        host: req.get("host"),
        hasSession: Boolean(req.session),
        hasBody: Boolean(req.body),
        bodyKeys: req.body ? Object.keys(req.body) : [],
      });

      return res.redirect(FRONTEND_LOGIN_REDIRECT);
    }

    samlDbg("SAML USER (from strategy verify)", {
      email: user.email,
      name: user.name,
      groupsType: Array.isArray(user.groups) ? "array" : typeof user.groups,
      groupsCount: Array.isArray(user.groups) ? user.groups.length : undefined,
    });

    const finishLogin = () => {
      req.login(user, (loginErr) => {
        if (loginErr) {
          console.error("❌ req.login failed:", loginErr);
          return next(loginErr);
        }

        // Your app’s flat session copy
        req.session.user = user;
        req.session.authenticated = true;

        req.session.save((saveErr) => {
          if (saveErr) {
            console.error("❌ session.save error:", saveErr);
            return next(saveErr);
          }

          samlDbg("LOGIN COMPLETE", {
            redirectingTo: FRONTEND_SUCCESS_REDIRECT,
            sessionUserEmail:
              req.session?.user?.email ||
              req.session?.passport?.user?.email ||
              null,
            hasPassport: Boolean(req.session?.passport),
          });

          return res.redirect(FRONTEND_SUCCESS_REDIRECT);
        });
      });
    };

    // Regenerate if available (helps avoid stale sessions)
    if (req.session?.regenerate) {
      req.session.regenerate((regenErr) => {
        if (regenErr) {
          console.error("❌ session.regenerate error:", regenErr);
          return finishLogin();
        }
        return finishLogin();
      });
    } else {
      return finishLogin();
    }
  })(req, res, next);
}

/**
 * ======================================================
 * Start SAML Login
 * GET /api/auth/saml/login
 * ======================================================
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
 * ======================================================
 * SAML Callback (Correct ACS)
 * POST /api/auth/saml/callback
 * ======================================================
 */
router.post("/saml/callback", handleSamlCallback);

/**
 * ======================================================
 * SAFETY ALIAS (Fixes your current 404)
 * Okta is currently POSTing to /api/auth/saml/login
 * so handle it like callback.
 * POST /api/auth/saml/login
 * ======================================================
 */
router.post("/saml/login", (req, res, next) => {
  samlDbg("POSTED TO /saml/login (alias to callback)", {
    url: req.originalUrl,
    host: req.get("host"),
    origin: req.get("origin"),
    bodyKeys: req.body ? Object.keys(req.body) : [],
  });

  return handleSamlCallback(req, res, next);
});

/**
 * ======================================================
 * Logout
 * GET /api/auth/logout
 * ======================================================
 */
router.get("/logout", (req, res) => {
  try {
    if (typeof req.logout === "function") req.logout(() => {});
  } catch {}

  req.session?.destroy(() => {
    res.clearCookie("eandi.sid");
    res.redirect(FRONTEND_LOGIN_REDIRECT);
  });
});

export default router;
