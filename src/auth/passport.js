// src/auth/passport.js
import passport from "passport";
import { Strategy as SamlStrategy } from "passport-saml";

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
  const first = (profile.firstName || profile.givenName || "")
    .toString()
    .trim();
  const last = (profile.lastName || profile.sn || "").toString().trim();
  const display = (profile.displayName || profile.name || profile.cn || "")
    .toString()
    .trim();

  if (display) return display;
  const full = `${first} ${last}`.trim();
  return full || profile.nameID || "";
}

function pickGroups(profile) {
  const g =
    profile.groups ||
    profile["http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"];
  return asArray(g);
}

/**
 * Option B:
 * Azure env var contains raw base64 from Okta metadata (<X509Certificate>...</X509Certificate>)
 * Convert it to PEM before giving to passport-saml.
 */
function normalizeOktaCert(raw) {
  if (!raw) return raw;

  let v = raw.trim();

  // Already PEM → just fix newline escapes
  if (v.includes("BEGIN CERTIFICATE")) {
    return v.replace(/\\n/g, "\n").trim();
  }

  // Raw base64 → wrap as PEM
  v = v.replace(/\s+/g, "");
  const lines = v.match(/.{1,64}/g)?.join("\n") || v;

  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----`;
}

/* ------------------------------------------------------
   Init Passport
------------------------------------------------------ */
export function initPassport() {
  const SAML_CALLBACK_URL = (process.env.SAML_CALLBACK_URL || "").trim();
  const OKTA_SSO_URL = (process.env.OKTA_SSO_URL || "").trim(); // Signon URL
  const SAML_ISSUER = (process.env.SAML_ISSUER || "").trim();
  const OKTA_X509_CERT = (process.env.OKTA_X509_CERT || "").trim();

  // Fail fast with clear errors
  if (!SAML_CALLBACK_URL) throw new Error("❌ Missing env: SAML_CALLBACK_URL");
  if (!OKTA_SSO_URL) throw new Error("❌ Missing env: OKTA_SSO_URL");
  if (!SAML_ISSUER) throw new Error("❌ Missing env: SAML_ISSUER");
  if (!OKTA_X509_CERT) throw new Error("❌ Missing env: OKTA_X509_CERT");

  passport.use(
    new SamlStrategy(
      {
        callbackUrl: SAML_CALLBACK_URL,
        entryPoint: OKTA_SSO_URL,
        issuer: SAML_ISSUER,

        // ✅ Option B fix here
        cert: normalizeOktaCert(OKTA_X509_CERT),

        wantAssertionsSigned: true,
        wantAuthnResponseSigned: true,
        identifierFormat: null,
      },
      (profile, done) => {
        try {
          return done(null, {
            email: pickEmail(profile),
            name: pickName(profile),
            groups: pickGroups(profile),
            okta_id: profile?.nameID || null,
          });
        } catch (err) {
          return done(err);
        }
      }
    )
  );

  passport.serializeUser((user, done) => done(null, user));
  passport.deserializeUser((user, done) => done(null, user));
}

export default passport;
