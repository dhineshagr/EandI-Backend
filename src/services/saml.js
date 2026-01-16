// src/services/saml.js
import dotenv from "dotenv";
dotenv.config();

import passport from "passport";
import { Strategy as SamlStrategy } from "passport-saml";

/* ------------------------------------------------------
   Required Environment Variables
------------------------------------------------------ */
const SAML_CALLBACK_URL = (process.env.SAML_CALLBACK_URL || "").trim();
const SAML_ISSUER = (process.env.SAML_ISSUER || "").trim();
const OKTA_SIGNON_URL = (process.env.OKTA_SIGNON_URL || "").trim();

// ✅ NEW: base64-encoded PEM cert stored in Azure App Settings
const OKTA_X509_CERT_B64 = (process.env.OKTA_X509_CERT_B64 || "").trim();

/* ------------------------------------------------------
   Fail fast
------------------------------------------------------ */
if (!SAML_CALLBACK_URL) throw new Error("❌ Missing env: SAML_CALLBACK_URL");
if (!SAML_ISSUER) throw new Error("❌ Missing env: SAML_ISSUER");
if (!OKTA_SIGNON_URL) throw new Error("❌ Missing env: OKTA_SIGNON_URL");
if (!OKTA_X509_CERT_B64) throw new Error("❌ Missing env: OKTA_X509_CERT_B64");

/* ------------------------------------------------------
   Helpers
------------------------------------------------------ */
function asArray(v) {
  if (!v) return [];
  if (Array.isArray(v)) return v.filter(Boolean);
  if (typeof v === "string") return v ? [v] : [];
  return [];
}

function pickEmail(profile) {
  return (
    profile.email ||
    profile.mail ||
    profile.upn ||
    profile.userPrincipalName ||
    profile.nameID ||
    profile[
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
    ] ||
    ""
  )
    .toString()
    .trim()
    .toLowerCase();
}

function pickName(profile) {
  return (
    profile.displayName ||
    profile.name ||
    profile.cn ||
    profile.givenName ||
    profile.nameID ||
    ""
  ).toString();
}

function pickGroups(profile) {
  const g =
    profile.groups ||
    profile["http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"];
  return asArray(g);
}

function decodePemFromB64(b64) {
  let v = String(b64 || "").trim();

  // remove wrapping quotes if Azure or pipeline added them
  if (
    (v.startsWith('"') && v.endsWith('"')) ||
    (v.startsWith("'") && v.endsWith("'"))
  ) {
    v = v.slice(1, -1).trim();
  }

  // remove whitespace/newlines in base64 itself
  v = v.replace(/\s+/g, "");

  const decoded = Buffer.from(v, "base64")
    .toString("utf8")
    .replace(/\\n/g, "\n")
    .trim();

  if (!decoded.includes("-----BEGIN CERTIFICATE-----")) {
    // Show only safe diagnostics (no secret dump)
    throw new Error(
      "❌ OKTA_X509_CERT_B64 decoded value is NOT a PEM certificate. " +
        "Please re-check the Azure App Setting value (must be base64 of the full PEM text)."
    );
  }

  return decoded;
}

/* ------------------------------------------------------
   Passport session wiring
------------------------------------------------------ */
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

/* ------------------------------------------------------
   Initialize Strategy
------------------------------------------------------ */
const signingCertPem = decodePemFromB64(OKTA_X509_CERT_B64);

console.log("✅ Okta signing cert decoded from OKTA_X509_CERT_B64", {
  startsWith: signingCertPem.split("\n")[0],
  length: signingCertPem.length,
});

passport.use(
  new SamlStrategy(
    {
      callbackUrl: SAML_CALLBACK_URL,
      entryPoint: OKTA_SIGNON_URL,
      issuer: SAML_ISSUER,

      // ✅ MUST be the correct SIGNING cert in PEM format
      cert: signingCertPem,

      identifierFormat: null,
      wantAssertionsSigned: true,
      wantAuthnResponseSigned: true,

      // Azure/Okta stability behind proxies
      validateInResponseTo: false,
      acceptedClockSkewMs: 5 * 60 * 1000,
      requestIdExpirationPeriodMs: 5 * 60 * 1000,
    },
    (profile, done) => {
      try {
        const email = pickEmail(profile);
        const groups = pickGroups(profile);

        return done(null, {
          email,
          name: pickName(profile),
          groups,
          roles: groups,
          user_type: "internal",
          nameID: profile.nameID,
        });
      } catch (err) {
        return done(err);
      }
    }
  )
);

console.log("✅ Okta SAML strategy initialized");
export default passport;
