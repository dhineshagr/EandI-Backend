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
    stackTop: (e?.stack || "").split("\n").slice(0, 6).join("\n"),
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

/**
 * Build a proper PEM from:
 * 1) RAW PEM string (BEGIN/END included)
 * 2) base64(PEM text)
 * 3) base64(cert-body only)
 */
function toPemCertificate(input) {
  if (!input) throw new Error("❌ Cert value is empty");

  let v = String(input).trim();

  // strip wrapping quotes sometimes added by pipelines
  if (
    (v.startsWith('"') && v.endsWith('"')) ||
    (v.startsWith("'") && v.endsWith("'"))
  ) {
    v = v.slice(1, -1).trim();
  }

  // If user pasted raw PEM into Azure setting, accept it
  if (v.includes("-----BEGIN CERTIFICATE-----")) {
    v = v.replace(/\\n/g, "\n").replace(/\r\n/g, "\n").trim();
    return normalizePem(v);
  }

  // Otherwise treat as base64 of something
  // remove whitespace/newlines in base64 value
  const b64 = v.replace(/\s+/g, "");

  let decoded;
  try {
    decoded = Buffer.from(b64, "base64").toString("utf8").trim();
  } catch (e) {
    throw new Error(
      "❌ OKTA_X509_CERT_B64 is not valid base64. Please re-check Azure App Setting."
    );
  }

  // decoded might be PEM text
  if (decoded.includes("-----BEGIN CERTIFICATE-----")) {
    decoded = decoded.replace(/\\n/g, "\n").replace(/\r\n/g, "\n").trim();
    return normalizePem(decoded);
  }

  // decoded might be cert-body only (no headers)
  // so build PEM from it
  const body = decoded.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/=]+$/.test(body)) {
    throw new Error(
      "❌ Decoded value is not PEM text and not a base64 certificate body. Azure value is likely wrong/double-encoded."
    );
  }

  const lines = body.match(/.{1,64}/g)?.join("\n") || body;
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----`;
}

function normalizePem(pem) {
  // normalize newlines + remove extra blank lines
  const cleaned = pem
    .replace(/\r\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  // Ensure header/footer exist
  if (
    !cleaned.includes("-----BEGIN CERTIFICATE-----") ||
    !cleaned.includes("-----END CERTIFICATE-----")
  ) {
    throw new Error("❌ PEM is missing BEGIN/END CERTIFICATE lines");
  }

  // Ensure body has 64-char wrapping (OpenSSL likes this)
  const body = cleaned
    .replace("-----BEGIN CERTIFICATE-----", "")
    .replace("-----END CERTIFICATE-----", "")
    .replace(/\s+/g, "")
    .trim();

  const wrapped = body.match(/.{1,64}/g)?.join("\n") || body;
  return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----`;
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
    rawLooksLikePem: OKTA_X509_CERT_B64.includes("-----BEGIN CERTIFICATE-----"),
    rawLen: OKTA_X509_CERT_B64.length,
    rawHasSpaces: /\s/.test(OKTA_X509_CERT_B64),
  });

  passport.serializeUser((user, done) => done(null, user));
  passport.deserializeUser((user, done) => done(null, user));

  // ✅ Accept raw PEM OR base64(PEM) OR base64(body)
  const signingCertPem = toPemCertificate(OKTA_X509_CERT_B64);

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
