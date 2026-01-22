// src/routes/auth.js
import { Router } from "express";
import passport from "passport";

const router = Router();

const FRONTEND_URL =
  process.env.FRONTEND_BASE_URL ||
  process.env.FRONTEND_URL ||
  "http://localhost:5173";

const DEBUG_SAML = true;
function samlDbg(label, obj) {
  if (!DEBUG_SAML) return;
  console.log(`🧩 [SAML DEBUG] ${label}`, obj || "");
}

function decodeSamlResponseSafe(b64) {
  try {
    const xml = Buffer.from(String(b64 || ""), "base64").toString("utf8");
    return {
      xmlLen: xml.length,
      hasEncryptedAssertion: /EncryptedAssertion/.test(xml),
      hasEncryptedData: /EncryptedData/.test(xml),
      hasSignature: /<ds:Signature|<Signature/.test(xml),
      xmlStartsWith: xml.slice(0, 120),
      issuer:
        (xml.match(/<(?:saml2:)?Issuer[^>]*>([^<]+)</)?.[1] || "").trim() ||
        null,
      destination:
        (xml.match(/Destination="([^"]+)"/)?.[1] || "").trim() || null,
      audience:
        (xml.match(/<(?:saml2:)?Audience[^>]*>([^<]+)</)?.[1] || "").trim() ||
        null,
    };
  } catch (e) {
    return { error: e?.message || String(e) };
  }
}

function isAllowedReturnUrl(url) {
  try {
    const u = new URL(url);
    const allowed = new Set([
      new URL(FRONTEND_URL).origin,
      // Add more allowed frontend origins here if needed
    ]);
    return allowed.has(u.origin);
  } catch {
    return false;
  }
}

function finalRedirectUrl(req) {
  const relay = req?.body?.RelayState || req?.query?.RelayState;

  if (relay && isAllowedReturnUrl(relay)) return relay;

  return `${FRONTEND_URL}/upload`;
}

/**
 * Start SAML Login
 * GET /api/auth/saml/login
 */
router.get("/saml/login", (req, res, next) => {
  samlDbg("START LOGIN", {
    method: req.method,
    path: req.originalUrl,
    host: req.get("host"),
    origin: req.get("origin"),
    referer: req.get("referer"),
    userAgent: req.get("user-agent"),
  });

  return passport.authenticate("saml")(req, res, next);
});

/**
 * OPTION B:
 * Accept POST to /saml/login (some Okta configs post here)
 */
router.post("/saml/login", (req, res, next) => {
  samlDbg("POSTED TO /saml/login (alias to callback)", {
    method: req.method,
    path: req.originalUrl,
    host: req.get("host"),
    origin: req.get("origin"),
    referer: req.get("referer"),
    contentType: req.get("content-type"),
    bodyKeys: Object.keys(req.body || {}),
    relayState: req?.body?.RelayState || "[missing]",
  });

  if (req?.body?.SAMLResponse) {
    samlDbg(
      "SAMLResponse diagnostics (safe)",
      decodeSamlResponseSafe(req.body.SAMLResponse)
    );
  }

  return passport.authenticate("saml", (err, user, info) => {
    if (err || !user) {
      console.error("❌ SAML CALLBACK FAILED", {
        err: err?.message || err,
        infoType: info ? typeof info : null,
      });
      return res.redirect(`${FRONTEND_URL}/login?error=saml_failed`);
    }

    req.login(user, (loginErr) => {
      if (loginErr) {
        console.error("❌ req.login() failed:", loginErr);
        return res.redirect(`${FRONTEND_URL}/login?error=session_failed`);
      }

      // ✅ IMPORTANT: store session in a consistent shape
      // matches SQL login: req.session.user = { authenticated: true, user: {...} }
      req.session.user = { authenticated: true, user };
      req.session.save(() => {});

      samlDbg("SAML SUCCESS (session stored)", {
        email: user.email,
        name: user.name,
        hasSession: !!req.session,
        redirectTo: finalRedirectUrl(req),
      });

      return res.redirect(finalRedirectUrl(req));
    });
  })(req, res, next);
});

/**
 * Real callback endpoint
 * POST /api/auth/saml/callback
 */
router.post("/saml/callback", (req, res, next) => {
  samlDbg("CALLBACK HIT (/saml/callback)", {
    method: req.method,
    path: req.originalUrl,
    host: req.get("host"),
    origin: req.get("origin"),
    referer: req.get("referer"),
    userAgent: req.get("user-agent"),
    contentType: req.get("content-type"),
    bodyKeys: Object.keys(req.body || {}),
    relayState: req?.body?.RelayState || "[missing]",
  });

  if (req?.body?.SAMLResponse) {
    samlDbg(
      "SAMLResponse diagnostics (safe)",
      decodeSamlResponseSafe(req.body.SAMLResponse)
    );
  }

  return passport.authenticate("saml", (err, user, info) => {
    if (err || !user) {
      console.error("❌ SAML CALLBACK FAILED", {
        err: err?.message || err,
        infoType: info ? typeof info : null,
      });
      return res.redirect(`${FRONTEND_URL}/login?error=saml_failed`);
    }

    req.login(user, (loginErr) => {
      if (loginErr) {
        console.error("❌ req.login() failed:", loginErr);
        return res.redirect(`${FRONTEND_URL}/login?error=session_failed`);
      }

      // ✅ IMPORTANT: store session in a consistent shape
      req.session.user = { authenticated: true, user };

      samlDbg("SAML SUCCESS (session stored)", {
        email: user.email,
        name: user.name,
        hasSession: !!req.session,
        redirectTo: finalRedirectUrl(req),
      });

      return res.redirect(finalRedirectUrl(req));
    });
  })(req, res, next);
});

/**
 * Logout
 * POST /api/auth/logout   (depending on how this router is mounted)
 */
// Logout
// POST /api/auth/logout
router.post("/logout", async (req, res) => {
  const isProd = String(process.env.NODE_ENV || "").toLowerCase() === "production";

  try {
    // 1) Passport logout (await safely)
    if (typeof req.logout === "function") {
      await new Promise((resolve) => {
        try {
          req.logout(() => resolve());
        } catch {
          resolve();
        }
      });
    }

    // 2) Clear custom session fields
    if (req.session) {
      req.session.user = null;
      req.session.passport = null;
    }

    // 3) Destroy the server session
    await new Promise((resolve) => {
      if (!req.session) return resolve();
      req.session.destroy(() => resolve());
    });

    // 4) Clear cookie (MUST match session config in server.js)
    res.clearCookie("eandi.sid", {
      path: "/",
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? "none" : "lax",
      maxAge: 0,   
    });

    // 5) Optional: Okta global logout redirect
    const oktaLogout = process.env.OKTA_LOGOUT_URL;
    if (oktaLogout) {
      return res.json({ success: true, redirect: oktaLogout });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error("❌ Logout failed:", err);
    return res.status(500).json({ success: false });
  }
});


export default router;
