// src/services/saml.js
import dotenv from "dotenv";
dotenv.config(); // REQUIRED

import passport from "passport";
import { Strategy as SamlStrategy } from "passport-saml";

/* ------------------------------------------------------
   Required Environment Variables
------------------------------------------------------ */
const SAML_CALLBACK_URL = process.env.SAML_CALLBACK_URL;
const SAML_ISSUER = process.env.SAML_ISSUER;
const OKTA_SIGNON_URL = process.env.OKTA_SIGNON_URL;
const OKTA_X509_CERT = process.env.OKTA_X509_CERT;

/* ------------------------------------------------------
  OKTA Certificate value issue
------------------------------------------------------ */
/*const oktaCert =
  process.env.OKTA_X509_CERT_B64
    ? Buffer.from(process.env.OKTA_X509_CERT_B64, "base64").toString("utf8")
    : process.env.OKTA_X509_CERT;*/

/* ------------------------------------------------------
   Fail fast with clear errors
------------------------------------------------------ */
if (!SAML_CALLBACK_URL) throw new Error("❌ Missing env: SAML_CALLBACK_URL");
if (!SAML_ISSUER) throw new Error("❌ Missing env: SAML_ISSUER");
if (!OKTA_SIGNON_URL) throw new Error("❌ Missing env: OKTA_SIGNON_URL");
if (!OKTA_X509_CERT) throw new Error("❌ Missing env: OKTA_X509_CERT");

/* ------------------------------------------------------
   Helpers
------------------------------------------------------ */ /* ------------------------------------------------------
   Helpers – normalize Okta cert (BASE64 → PEM)
------------------------------------------------------ */
function normalizeOktaCert(raw) {
  if (!raw) return raw;

  let v = raw.trim();

  // Case 1: already PEM → just fix newlines
  if (v.includes("BEGIN CERTIFICATE")) {
    return v.replace(/\\n/g, "\n").trim();
  }

  // Case 2: raw base64 from Okta metadata
  v = v.replace(/\s+/g, "");
  const lines = v.match(/.{1,64}/g)?.join("\n") || v;

  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----`;
}

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

      cert: OKTA_X509_CERT.replace(/\\n/g, "\n"),

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
          roles: groups, // keep consistent for your auth checks
          user_type: "internal",

          // helpful to keep for troubleshooting (optional)
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
