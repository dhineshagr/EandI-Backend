// src/routes/auth.js
import { Router } from "express";
import passport from "passport";
import { parseStringPromise } from "xml2js";

const router = Router();

const FRONTEND_URL =
  process.env.FRONTEND_BASE_URL ||
  process.env.FRONTEND_URL ||
  "http://localhost:5173";

const DEBUG_SAML =
  String(process.env.DEBUG_SAML || "true").toLowerCase() === "true";

function samlLog(label, obj) {
  if (!DEBUG_SAML) return;
  console.log(`🧩 [SAML DEBUG] ${label}`, obj || "");
}

function safeHeaderSnapshot(req) {
  const h = req.headers || {};
  return {
    method: req.method,
    path: req.originalUrl,
    host: req.get("host"),
    origin: req.get("origin"),
    referer: req.get("referer"),
    userAgent: req.get("user-agent"),
    contentType: req.get("content-type"),
    xfProto: h["x-forwarded-proto"],
    xfHost: h["x-forwarded-host"],
    xfFor: h["x-forwarded-for"]
      ? String(h["x-forwarded-for"]).split(",")[0].trim()
      : undefined,
    hasCookieHeader: !!h.cookie,
  };
}

function safeBase64Len(v) {
  return v ? String(v).length : 0;
}

function tryDecodeSamlXml(samlResponseB64) {
  try {
    const b64 = String(samlResponseB64 || "")
      .trim()
      .replace(/\s+/g, "");
    if (!b64) return { ok: false, reason: "empty" };
    const xml = Buffer.from(b64, "base64").toString("utf8");
    return { ok: true, xml, xmlLen: xml.length };
  } catch (e) {
    return { ok: false, reason: e?.message || String(e) };
  }
}

// quick “cheap” checks without full parsing
function cheapXmlSignals(xml) {
  const hasEncryptedAssertion =
    xml.includes("<EncryptedAssertion") || xml.includes(":EncryptedAssertion");
  const hasEncryptedData =
    xml.includes("<xenc:EncryptedData") || xml.includes(":EncryptedData");
  const hasSignature =
    xml.includes("<ds:Signature") || xml.includes(":Signature");
  return { hasEncryptedAssertion, hasEncryptedData, hasSignature };
}

// deeper parsing to find algorithms / destination / audience etc.
async function extractSamlDiagnostics(xml) {
  // xml2js can be strict; keep it tolerant
  const parsed = await parseStringPromise(xml, {
    explicitArray: true,
    tagNameProcessors: [],
    attrNameProcessors: [],
    ignoreAttrs: false,
    explicitRoot: true,
    trim: true,
  });

  // NOTE: names differ depending on namespaces; we try best-effort.
  // We'll also do some regex fallback.
  const diag = {
    issuer: null,
    destination: null,
    audience: null,
    inResponseTo: null,
    notOnOrAfter: null,
    signatureMethod: null,
    digestMethod: null,
  };

  // Regex fallback for algorithms + destination/audience
  const sigAlgMatch =
    xml.match(/SignatureMethod[^>]*Algorithm="([^"]+)"/i) ||
    xml.match(/SignatureMethod[^>]*Algorithm='([^']+)'/i);
  const digAlgMatch =
    xml.match(/DigestMethod[^>]*Algorithm="([^"]+)"/i) ||
    xml.match(/DigestMethod[^>]*Algorithm='([^']+)'/i);
  const destMatch =
    xml.match(/Destination="([^"]+)"/i) || xml.match(/Destination='([^']+)'/i);
  const inRespMatch =
    xml.match(/InResponseTo="([^"]+)"/i) ||
    xml.match(/InResponseTo='([^']+)'/i);
  const noaMatch =
    xml.match(/NotOnOrAfter="([^"]+)"/i) ||
    xml.match(/NotOnOrAfter='([^']+)'/i);

  diag.signatureMethod = sigAlgMatch?.[1] || null;
  diag.digestMethod = digAlgMatch?.[1] || null;
  diag.destination = destMatch?.[1] || null;
  diag.inResponseTo = inRespMatch?.[1] || null;
  diag.notOnOrAfter = noaMatch?.[1] || null;

  // issuer & audience regex fallback
  const issuerMatch = xml.match(
    /<\s*(?:saml2?:)?Issuer[^>]*>([^<]+)<\/\s*(?:saml2?:)?Issuer\s*>/i
  );
  if (issuerMatch?.[1]) diag.issuer = issuerMatch[1].trim();

  const audienceMatch = xml.match(
    /<\s*(?:saml2?:)?Audience[^>]*>([^<]+)<\/\s*(?:saml2?:)?Audience\s*>/i
  );
  if (audienceMatch?.[1]) diag.audience = audienceMatch[1].trim();

  // We return best-effort even if parsed isn’t used deeply
  return diag;
}

async function logSamlRequestDetails(req) {
  const body = req.body || {};
  const samlResponseB64 = body.SAMLResponse;
  const relayState = body.RelayState;

  samlLog("SAML REQUEST META", {
    ...safeHeaderSnapshot(req),
    bodyKeys: Object.keys(body),
    hasSAMLResponse: !!samlResponseB64,
    samlResponseB64Len: safeBase64Len(samlResponseB64),
    relayState: relayState ? String(relayState).slice(0, 140) : null,
  });

  if (!samlResponseB64) return;

  const decoded = tryDecodeSamlXml(samlResponseB64);
  if (!decoded.ok) {
    samlLog("SAMLResponse decode FAILED", { reason: decoded.reason });
    return;
  }

  const xml = decoded.xml;
  const signals = cheapXmlSignals(xml);

  samlLog("SAMLResponse decoded (safe)", {
    xmlLen: decoded.xmlLen,
    ...signals,
    xmlStartsWith: xml.slice(0, 80),
  });

  // Try deeper extraction (best-effort)
  try {
    const diag = await extractSamlDiagnostics(xml);
    samlLog("SAMLResponse diagnostics (safe)", diag);

    // Very useful hint
    if (signals.hasEncryptedAssertion || signals.hasEncryptedData) {
      samlLog("LIKELY ROOT CAUSE", {
        message:
          "Okta is sending an ENCRYPTED assertion. passport-saml cannot decrypt unless you configure decryptionPvk (private key). " +
          "Ask Okta admin to disable Assertion Encryption for this app.",
      });
    }

    if (
      diag.destination &&
      !diag.destination.includes("/api/auth/saml/callback")
    ) {
      samlLog("POSSIBLE ROOT CAUSE", {
        message:
          `Destination/ACS in SAMLResponse is '${diag.destination}'. ` +
          "It should match your ACS URL (/api/auth/saml/callback) unless you intentionally accept /saml/login. " +
          "Ask Okta admin to confirm Single sign-on URL (ACS URL).",
      });
    }
  } catch (e) {
    samlLog("SAMLResponse diagnostics parse FAILED", { err: e?.message || e });
  }
}

/**
 * Start SAML Login
 * GET /api/auth/saml/login
 */
router.get("/saml/login", (req, res, next) => {
  samlLog("START LOGIN", safeHeaderSnapshot(req));
  return passport.authenticate("saml")(req, res, next);
});

/**
 * ✅ OPTION B
 * Okta is POSTing SAMLResponse to /api/auth/saml/login (not /callback)
 * So we accept POST here and treat it exactly like the callback.
 *
 * POST /api/auth/saml/login
 */
router.post("/saml/login", async (req, res, next) => {
  await logSamlRequestDetails(req);

  return passport.authenticate("saml", (err, user, info) => {
    if (err || !user) {
      console.error("❌ SAML CALLBACK FAILED", {
        err: err?.message || err,
        // info can sometimes be huge; print minimally
        infoType: info ? typeof info : null,
      });

      // Extra hint if OpenSSL decoder error
      const msg = String(err?.message || "");
      if (msg.includes("DECODER routines::unsupported")) {
        console.error(
          "❗ HINT: This often happens when the assertion is encrypted OR the signature/cert format doesn't match what passport-saml expects. Check logs above for EncryptedAssertion and algorithms."
        );
      }

      return res.redirect(`${FRONTEND_URL}/login?error=saml_failed`);
    }

    // ✅ create passport session
    req.login(user, (loginErr) => {
      if (loginErr) {
        console.error("❌ req.login() failed:", loginErr?.message || loginErr);
        return res.redirect(`${FRONTEND_URL}/login?error=session_failed`);
      }

      // ✅ store flat user for your middleware
      req.session.user = user;

      samlLog("SAML SUCCESS (session stored)", {
        email: user.email,
        name: user.name,
        hasSession: !!req.session,
        sessionId: req.sessionID
          ? String(req.sessionID).slice(0, 8) + "***"
          : null,
      });

      return res.redirect(`${FRONTEND_URL}/upload`);
    });
  })(req, res, next);
});

/**
 * Keep the real callback endpoint too
 * POST /api/auth/saml/callback
 */
router.post("/saml/callback", async (req, res, next) => {
  samlLog("CALLBACK HIT (/saml/callback)", safeHeaderSnapshot(req));
  await logSamlRequestDetails(req);

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
        console.error("❌ req.login() failed:", loginErr?.message || loginErr);
        return res.redirect(`${FRONTEND_URL}/login?error=session_failed`);
      }

      req.session.user = user;

      samlLog("SAML SUCCESS (session stored)", {
        email: user.email,
        name: user.name,
        hasSession: !!req.session,
      });

      return res.redirect(`${FRONTEND_URL}/upload`);
    });
  })(req, res, next);
});

export default router;
