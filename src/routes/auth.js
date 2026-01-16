// src/routes/auth.js
import { Router } from "express";
import passport from "passport";

const router = Router();

const FRONTEND_URL =
  process.env.FRONTEND_BASE_URL ||
  process.env.FRONTEND_URL ||
  "http://localhost:5173";

const DEBUG_SAML = true;

function dbg(label, obj) {
  if (!DEBUG_SAML) return;
  if (obj) console.log(`🧩 [SAML DEBUG] ${label}`, obj);
  else console.log(`🧩 [SAML DEBUG] ${label}`);
}

function safeErr(e) {
  return {
    message: e?.message || String(e),
    name: e?.name,
    code: e?.code,
    stackTop: (e?.stack || "").split("\n").slice(0, 8).join("\n"),
  };
}

function logReq(req, label) {
  dbg(label, {
    method: req.method,
    path: req.originalUrl,
    host: req.get("host"),
    origin: req.get("origin"),
    referer: req.get("referer"),
    userAgent: req.get("user-agent"),
    contentType: req.get("content-type"),
    xfProto: req.get("x-forwarded-proto"),
    xfFor: req.get("x-forwarded-for"),
    hasCookieHeader: !!req.headers.cookie,
    bodyKeys: Object.keys(req.body || {}),
    relayState: req.body?.RelayState || "[missing]",
    samlResponseB64Len: req.body?.SAMLResponse
      ? String(req.body.SAMLResponse).length
      : 0,
  });
}

/**
 * GET /api/auth/saml/login
 */
router.get("/saml/login", (req, res, next) => {
  logReq(req, "START LOGIN");

  // show strategies present right now (helps confirm registration)
  dbg("PASSPORT STRATEGIES", {
    strategies: Object.keys(passport._strategies || {}),
  });

  return passport.authenticate("saml")(req, res, next);
});

/**
 * POST /api/auth/saml/callback
 */
router.post("/saml/callback", (req, res, next) => {
  logReq(req, "CALLBACK HIT (/saml/callback)");

  return passport.authenticate("saml", (err, user, info) => {
    if (err || !user) {
      console.error("❌ SAML CALLBACK FAILED", {
        err: safeErr(err),
        infoType: info ? typeof info : null,
        info,
      });
      return res.redirect(`${FRONTEND_URL}/login?error=saml_failed`);
    }

    req.login(user, (loginErr) => {
      if (loginErr) {
        console.error("❌ req.login() failed:", safeErr(loginErr));
        return res.redirect(`${FRONTEND_URL}/login?error=session_failed`);
      }

      req.session.user = user;

      dbg("SAML SUCCESS (session stored)", {
        email: user.email,
        name: user.name,
        hasSession: !!req.session,
      });

      return res.redirect(`${FRONTEND_URL}/upload`);
    });
  })(req, res, next);
});

/**
 * OPTIONAL: keep OPTION-B alias if Okta posts to /login sometimes
 * POST /api/auth/saml/login
 */
router.post("/saml/login", (req, res, next) => {
  logReq(req, "POSTED TO /saml/login (alias)");

  return passport.authenticate("saml", (err, user, info) => {
    if (err || !user) {
      console.error("❌ SAML LOGIN-POST FAILED", {
        err: safeErr(err),
        infoType: info ? typeof info : null,
        info,
      });
      return res.redirect(`${FRONTEND_URL}/login?error=saml_failed`);
    }

    req.login(user, (loginErr) => {
      if (loginErr) {
        console.error("❌ req.login() failed:", safeErr(loginErr));
        return res.redirect(`${FRONTEND_URL}/login?error=session_failed`);
      }

      req.session.user = user;

      dbg("SAML SUCCESS (session stored)", {
        email: user.email,
        name: user.name,
        hasSession: !!req.session,
      });

      return res.redirect(`${FRONTEND_URL}/upload`);
    });
  })(req, res, next);
});

export default router;
