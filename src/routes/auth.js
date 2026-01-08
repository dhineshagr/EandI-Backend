// src/routes/auth.js
import { Router } from "express";
import passport from "passport";

const router = Router();
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

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
 * SAML Callback
 * POST /api/auth/saml/callback
 *
 * ✅ This version:
 * - Logs WHY SAML is failing (err/info)
 * - Calls req.login(user) so passport stores session properly
 * - Stores a flat user at req.session.user (your middleware expects this)
 */
router.post("/saml/callback", (req, res, next) => {
  passport.authenticate("saml", (err, user, info) => {
    if (err || !user) {
      console.error("❌ SAML CALLBACK FAILED", {
        err: err?.message || err,
        info,
      });

      // Helpful extra debugging
      samlDbg("CALLBACK REQUEST META", {
        method: req.method,
        url: req.originalUrl,
        origin: req.get("origin"),
        host: req.get("host"),
        hasSession: Boolean(req.session),
        hasBody: Boolean(req.body),
        bodyKeys: req.body ? Object.keys(req.body) : [],
      });

      return res.redirect(`${FRONTEND_URL}/login`);
    }

    // ✅ At this point SAML succeeded and we have a user profile
    samlDbg("SAML USER (from strategy verify)", {
      email: user.email,
      name: user.name,
      groupsType: Array.isArray(user.groups) ? "array" : typeof user.groups,
      groupsCount: Array.isArray(user.groups) ? user.groups.length : undefined,
    });

    // (Optional) regenerate session to prevent stale session issues
    const finishLogin = () => {
      // ✅ Ensure passport session is established
      req.login(user, (loginErr) => {
        if (loginErr) {
          console.error("❌ req.login failed:", loginErr);
          return next(loginErr);
        }

        // ✅ Keep YOUR app’s flat session copy
        req.session.user = user;
        req.session.authenticated = true;

        // ✅ Make sure cookie gets written
        req.session.save((saveErr) => {
          if (saveErr) {
            console.error("❌ session.save error:", saveErr);
            return next(saveErr);
          }

          samlDbg("LOGIN COMPLETE", {
            sessionUserEmail:
              req.session?.user?.email ||
              req.session?.passport?.user?.email ||
              null,
            hasPassport: Boolean(req.session?.passport),
          });

          return res.redirect(`${FRONTEND_URL}/`);
        });
      });
    };

    // Regenerate only if session exists
    if (req.session?.regenerate) {
      req.session.regenerate((regenErr) => {
        if (regenErr) {
          console.error("❌ session.regenerate error:", regenErr);
          // continue without blocking
          return finishLogin();
        }
        return finishLogin();
      });
    } else {
      return finishLogin();
    }
  })(req, res, next);
});

/**
 * Logout
 * GET /api/auth/logout
 */
router.get("/logout", (req, res) => {
  try {
    if (typeof req.logout === "function") req.logout(() => {});
  } catch {}

  req.session?.destroy(() => {
    res.clearCookie("eandi.sid");
    res.redirect(`${FRONTEND_URL}/login`);
  });
});

export default router;
