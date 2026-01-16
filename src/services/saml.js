// src/services/saml.js
import dotenv from "dotenv";
dotenv.config();

import passport from "passport";
import { Strategy as SamlStrategy } from "passport-saml";
import crypto from "crypto";

const DEBUG_SAML_INIT = true;

function slog(label, obj) {
  if (!DEBUG_SAML_INIT) return;
  if (obj) console.log(`🧩 [SAML INIT] ${label}`, obj);
  else console.log(`🧩 [SAML INIT] ${label}`);
}

function safeErr(e) {
  return {
    message: e?.message || String(e),
    name: e?.name,
    code: e?.code,
    stackTop: (e?.stack || "").split("\n").slice(0, 8).join("\n"),
  };
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

  // strip quotes if azure/pipeline wrapped it
  if (
    (v.startsWith('"') && v.endsWith('"')) ||
    (v.startsWith("'") && v.endsWith("'"))
  ) {
    v = v.slice(1, -1).trim();
  }

  // remove whitespace in base64
  v = v.replace(/\s+/g, "");

  const decoded = Buffer.from(v, "base64")
    .toString("utf8")
    .replace(/\\n/g, "\n")
    .replace(/\r\n/g, "\n")
    .trim();

  if (!decoded.includes("-----BEGIN CERTIFICATE-----")) {
    throw new Error(
      "❌ OKTA_X509_CERT_B64 decoded value is NOT PEM. Must be base64(full PEM text)."
    );
  }
  return decoded;
}

function inspectCertPem(pem) {
  try {
    const x509 = new crypto.X509Certificate(pem);
    return {
      ok: true,
      subject: x509.subject,
      issuer: x509.issuer,
      validFrom: x509.validFrom,
      validTo: x509.validTo,
      fingerprint256: x509.fingerprint256,
      serialNumber: x509.serialNumber,
      keyType: x509.publicKey?.asymmetricKeyType,
    };
  } catch (e) {
    return { ok: false, error: safeErr(e) };
  }
}

let _initialized = false;

export function initSamlStrategy() {
  if (_initialized) {
    slog("initSamlStrategy() called again - skipped");
    return passport;
  }
  _initialized = true;

  const SAML_CALLBACK_URL = (process.env.SAML_CALLBACK_URL || "").trim();
  const SAML_ISSUER = (process.env.SAML_ISSUER || "").trim();
  const OKTA_SIGNON_URL = (process.env.OKTA_SIGNON_URL || "").trim();
  const OKTA_X509_CERT_B64 = (process.env.OKTA_X509_CERT_B64 || "").trim();

  if (!SAML_CALLBACK_URL) throw new Error("❌ Missing env: SAML_CALLBACK_URL");
  if (!SAML_ISSUER) throw new Error("❌ Missing env: SAML_ISSUER");
  if (!OKTA_SIGNON_URL) throw new Error("❌ Missing env: OKTA_SIGNON_URL");
  if (!OKTA_X509_CERT_B64)
    throw new Error("❌ Missing env: OKTA_X509_CERT_B64");

  slog("ENV SUMMARY", {
    node: process.version,
    NODE_ENV: process.env.NODE_ENV,
    SAML_CALLBACK_URL,
    SAML_ISSUER,
    OKTA_SIGNON_URL,
    OKTA_X509_CERT_B64: OKTA_X509_CERT_B64 ? "[set]" : "[missing]",
  });

  // session wiring
  passport.serializeUser((user, done) => done(null, user));
  passport.deserializeUser((user, done) => done(null, user));

  const signingCertPem = decodePemFromB64(OKTA_X509_CERT_B64);

  slog("CERT STRING (SAFE)", {
    firstLine: signingCertPem.split("\n")[0],
    lastLine: signingCertPem.split("\n").slice(-1)[0],
    length: signingCertPem.length,
    lines: signingCertPem.split("\n").length,
  });

  const certInfo = inspectCertPem(signingCertPem);
  slog("CERT PARSE (crypto.X509Certificate)", certInfo);

  if (!certInfo.ok) {
    throw new Error(
      `❌ Cert cannot be parsed under Node/OpenSSL in Azure. ${certInfo.error?.message}`
    );
  }

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

        validateInResponseTo: false,
        acceptedClockSkewMs: 5 * 60 * 1000,
        requestIdExpirationPeriodMs: 5 * 60 * 1000,
      },
      (profile, done) => {
        try {
          const email = pickEmail(profile);
          const groups = pickGroups(profile);

          slog("PROFILE RECEIVED (SAFE)", {
            hasProfile: !!profile,
            nameID: profile?.nameID,
            email,
            groupsCount: groups.length,
            profileKeys: profile ? Object.keys(profile) : [],
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
          slog("PROFILE ERROR", safeErr(err));
          return done(err);
        }
      }
    )
  );

  slog("STRATEGY REGISTERED", {
    strategies: Object.keys(passport._strategies || {}),
  });

  return passport;
}

export default passport;
