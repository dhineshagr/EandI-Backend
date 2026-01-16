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
const OKTA_X509_CERT = (process.env.OKTA_X509_CERT || "").trim();

/* ------------------------------------------------------
   Fail fast with clear errors
------------------------------------------------------ */
if (!SAML_CALLBACK_URL) throw new Error("❌ Missing env: SAML_CALLBACK_URL");
if (!SAML_ISSUER) throw new Error("❌ Missing env: SAML_ISSUER");
if (!OKTA_SIGNON_URL) throw new Error("❌ Missing env: OKTA_SIGNON_URL");
if (!OKTA_X509_CERT) throw new Error("❌ Missing env: OKTA_X509_CERT");

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

/**
 * ✅ Normalize Okta cert from env to PEM.
 * Supports:
 *  A) PEM (-----BEGIN CERTIFICATE-----)
 *  B) Raw base64 from Okta metadata (<X509Certificate>...</X509Certificate>)
 *  C) Base64-encoded PEM text (often starts with LS0tLS1CRUdJTi...)
 */
function normalizeOktaCert(raw) {
  if (!raw) return raw;

  let v = String(raw).trim();

  // remove accidental wrapping quotes
  if (
    (v.startsWith('"') && v.endsWith('"')) ||
    (v.startsWith("'") && v.endsWith("'"))
  ) {
    v = v.slice(1, -1).trim();
  }

  // A) Already PEM
  if (v.includes("BEGIN CERTIFICATE")) {
    return v.replace(/\\n/g, "\n").trim();
  }

  // Try decode as base64 (handles C: base64-encoded PEM)
  const looksBase64 = /^[A-Za-z0-9+/=\s]+$/.test(v) && v.length > 100;
  if (looksBase64) {
    try {
      const decoded = Buffer.from(v.replace(/\s+/g, ""), "base64").toString(
        "utf8"
      );
      if (decoded.includes("BEGIN CERTIFICATE")) {
        return decoded.replace(/\\n/g, "\n").trim();
      }
    } catch {
      // ignore and fall through
    }
  }

  // B) Raw base64 cert → wrap as PEM
  v = v.replace(/\s+/g, "");
  const lines = v.match(/.{1,64}/g)?.join("\n") || v;

  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----`;
}

/* ------------------------------------------------------
   Passport session wiring
------------------------------------------------------ */
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

/* ------------------------------------------------------
   SAML Strategy
------------------------------------------------------ */
passport.use(
  new SamlStrategy(
    {
      callbackUrl: SAML_CALLBACK_URL,
      entryPoint: OKTA_SIGNON_URL,
      issuer: SAML_ISSUER,

      // ✅ THIS is the actual fix
      cert: normalizeOktaCert(OKTA_X509_CERT),

      identifierFormat: null,
      wantAssertionsSigned: true,
      wantAuthnResponseSigned: true,
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

console.log("✅ Okta SAML strategy initialized (cert normalized)");
export default passport;
