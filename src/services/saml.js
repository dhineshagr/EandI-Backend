// src/services/saml.js
import passport from "passport";
import { Strategy as SamlStrategy } from "passport-saml";

const DEBUG_SAML_INIT = true;

function log(label, obj) {
  if (!DEBUG_SAML_INIT) return;
  console.log(`🧩 [SAML INIT] ${label}`, obj || "");
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

function decodePemFromB64(b64) {
  let v = String(b64 || "").trim();

  if (
    (v.startsWith('"') && v.endsWith('"')) ||
    (v.startsWith("'") && v.endsWith("'"))
  ) {
    v = v.slice(1, -1).trim();
  }

  v = v.replace(/\s+/g, "");

  const decoded = Buffer.from(v, "base64")
    .toString("utf8")
    .replace(/\\n/g, "\n")
    .trim();

  if (!decoded.includes("-----BEGIN CERTIFICATE-----")) {
    throw new Error(
      "OKTA_X509_CERT_B64 is not a valid base64-encoded PEM certificate (missing BEGIN CERTIFICATE)."
    );
  }

  return decoded;
}

export function initSamlStrategy() {
  const SAML_CALLBACK_URL = (process.env.SAML_CALLBACK_URL || "").trim();
  const SAML_ISSUER = (process.env.SAML_ISSUER || "").trim();
  const OKTA_SIGNON_URL = (process.env.OKTA_SIGNON_URL || "").trim();
  const OKTA_X509_CERT_B64 = (process.env.OKTA_X509_CERT_B64 || "").trim();

  log("ENV SUMMARY", {
    NODE_ENV: process.env.NODE_ENV,
    SAML_CALLBACK_URL: SAML_CALLBACK_URL ? "[set]" : "[missing]",
    SAML_ISSUER: SAML_ISSUER ? "[set]" : "[missing]",
    OKTA_SIGNON_URL: OKTA_SIGNON_URL ? "[set]" : "[missing]",
    OKTA_X509_CERT_B64: OKTA_X509_CERT_B64 ? "[set]" : "[missing]",
  });

  if (!SAML_CALLBACK_URL) throw new Error("Missing env: SAML_CALLBACK_URL");
  if (!SAML_ISSUER) throw new Error("Missing env: SAML_ISSUER");
  if (!OKTA_SIGNON_URL) throw new Error("Missing env: OKTA_SIGNON_URL");
  if (!OKTA_X509_CERT_B64) throw new Error("Missing env: OKTA_X509_CERT_B64");

  const signingCertPem = decodePemFromB64(OKTA_X509_CERT_B64);

  // Safe fingerprint (not secret)
  const fp = signingCertPem.replace(/-----.*?-----|\s+/g, "").slice(0, 60);

  log("CERT LOADED", {
    startsWith: signingCertPem.split("\n")[0],
    length: signingCertPem.length,
    fp60: fp,
  });

  passport.serializeUser((user, done) => done(null, user));
  passport.deserializeUser((user, done) => done(null, user));

  passport.use(
    "saml",
    new SamlStrategy(
      {
        callbackUrl: SAML_CALLBACK_URL,
        entryPoint: OKTA_SIGNON_URL,
        issuer: SAML_ISSUER,
        cert: signingCertPem,

        identifierFormat: null,
        wantAssertionsSigned: true,
        wantAuthnResponseSigned: true,

        // Azure/Okta stability
        validateInResponseTo: false,
        acceptedClockSkewMs: 5 * 60 * 1000,
        requestIdExpirationPeriodMs: 5 * 60 * 1000,
      },
      (profile, done) => {
        try {
          const email = pickEmail(profile);
          const groups = pickGroups(profile);

          log("PROFILE RECEIVED", {
            hasProfile: !!profile,
            email,
            groupsCount: groups.length,
            nameID: profile?.nameID,
            keys: profile ? Object.keys(profile) : [],
          });

          return done(null, {
            email,
            name: pickName(profile),
            groups,
            roles: groups,
            user_type: "internal",
            nameID: profile?.nameID,
          });
        } catch (err) {
          return done(err);
        }
      }
    )
  );

  log("STRATEGY REGISTERED", {
    strategies: Object.keys(passport._strategies || {}),
  });
}

export default passport;
