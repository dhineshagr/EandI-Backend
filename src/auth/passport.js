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
 * Normalize Okta cert from env to PEM that passport-saml expects.
 * Supports:
 *  A) PEM directly (-----BEGIN CERTIFICATE-----)
 *  B) Raw base64 from Okta metadata (<X509Certificate>...</X509Certificate>)
 *  C) Base64 *encoded PEM text* (often starts with LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t)
 */
function normalizeOktaCert(raw) {
  if (!raw) return raw;

  let v = String(raw).trim();

  // Remove wrapping quotes if pasted accidentally
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

  // Try decode as base64 (handles case C: base64-encoded PEM)
  // Only attempt if it "looks like" base64
  const looksBase64 = /^[A-Za-z0-9+/=\s]+$/.test(v) && v.length > 100;
  if (looksBase64) {
    try {
      const decoded = Buffer.from(v.replace(/\s+/g, ""), "base64").toString(
        "utf8"
      );
      if (decoded.includes("BEGIN CERTIFICATE")) {
        return decoded.replace(/\\n/g, "\n").trim();
      }
      // If decode didn't produce PEM, fall through and treat v as raw base64 cert (case B)
    } catch {
      // ignore and fall through
    }
  }

  // B) Raw base64 cert from metadata → wrap as PEM
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

        // ✅ fixed
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
