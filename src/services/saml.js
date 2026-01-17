// src/services/saml.js
import dotenv from "dotenv";
dotenv.config();

import passport from "passport";
import { Strategy as SamlStrategy } from "passport-saml";
import crypto from "crypto";
import https from "https";
import { parseStringPromise } from "xml2js";

/**
 * Cert sources supported (priority):
 *  1) OKTA_X509_CERT_PEM  (raw PEM text)
 *  2) OKTA_X509_CERT_B64  (base64 of PEM text OR base64 of DER/binary cert OR base64 of cert body)
 *  3) OKTA_METADATA_URL   (fetch metadata and extract signing cert)
 *
 * Required:
 *  SAML_CALLBACK_URL, SAML_ISSUER, OKTA_SIGNON_URL
 */

const DEBUG_SAML = true;
function slog(label, obj) {
  if (!DEBUG_SAML) return;
  const ts = new Date().toISOString();
  console.log(`🧩 [SAML INIT] ${ts} ${label}`, obj || "");
}

function safeErr(e) {
  return {
    message: e?.message || String(e),
    name: e?.name,
    code: e?.code,
    stackTop: (e?.stack || "").split("\n").slice(0, 4).join("\n"),
  };
}

function stripWrappingQuotes(v) {
  let s = String(v || "").trim();
  if (
    (s.startsWith('"') && s.endsWith('"')) ||
    (s.startsWith("'") && s.endsWith("'"))
  ) {
    s = s.slice(1, -1).trim();
  }
  return s;
}

function normalizePem(pem) {
  let v = stripWrappingQuotes(pem);

  // Convert literal \n to newlines
  v = v.replace(/\\n/g, "\n").trim();

  // Remove BOM if any
  v = v.replace(/^\uFEFF/, "");

  // Ensure BEGIN/END are on their own lines
  if (v.includes("-----BEGIN CERTIFICATE-----") && !v.includes("\n")) {
    v = v
      .replace("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n")
      .replace("-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----");
  }

  return v.trim();
}

function httpGet(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve(data));
      })
      .on("error", reject);
  });
}

function wrapCertBodyToPem(certBodyB64) {
  const body = String(certBodyB64 || "").replace(/\s+/g, "");
  const lines = body.match(/.{1,64}/g)?.join("\n") || body;
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----`;
}

async function loadOktaCertFromMetadata(metadataUrl) {
  const xml = await httpGet(metadataUrl);
  const parsed = await parseStringPromise(xml);

  const entity = parsed?.EntityDescriptor;
  const idp = entity?.IDPSSODescriptor?.[0];
  const keyDescriptors = idp?.KeyDescriptor || [];

  let certB64 = null;

  for (const kd of keyDescriptors) {
    const use = kd?.$?.use;
    if (use && use !== "signing") continue;

    const x509 =
      kd?.KeyInfo?.[0]?.X509Data?.[0]?.X509Certificate?.[0] ||
      kd?.KeyInfo?.[0]?.["ds:X509Data"]?.[0]?.["ds:X509Certificate"]?.[0];

    if (x509) {
      certB64 = String(x509).replace(/\s+/g, "");
      break;
    }
  }

  if (!certB64) {
    throw new Error("❌ Could not extract X509Certificate from Okta metadata");
  }

  return wrapCertBodyToPem(certB64);
}

function inspectCertPem(pem) {
  const normalized = normalizePem(pem);
  const lines = normalized.split("\n").filter(Boolean);

  slog("CERT STRING (SAFE)", {
    firstLine: lines[0],
    lastLine: lines[lines.length - 1],
    length: normalized.length,
    lines: lines.length,
    hasBegin: normalized.includes("BEGIN CERTIFICATE"),
    hasEnd: normalized.includes("END CERTIFICATE"),
  });

  try {
    // eslint-disable-next-line no-new
    new crypto.X509Certificate(normalized);
    slog("CERT PARSE (crypto.X509Certificate)", { ok: true });
    return { ok: true, pem: normalized };
  } catch (e) {
    slog("CERT PARSE (crypto.X509Certificate)", {
      ok: false,
      error: safeErr(e),
    });
    return { ok: false, pem: normalized, error: e };
  }
}

function isBase64Like(v) {
  const s = String(v || "").replace(/\s+/g, "");
  if (s.length < 100) return false;
  return /^[A-Za-z0-9+/=]+$/.test(s);
}

/**
 * ✅ Converts OKTA_X509_CERT_B64 to PEM.
 * Supports:
 *  - base64(PEM text)
 *  - base64(DER/binary cert)
 *  - base64(cert body only)  -> wraps into PEM
 */
function pemFromOktaB64(b64Value) {
  const raw = stripWrappingQuotes(b64Value).replace(/\s+/g, "");
  if (!raw) return "";

  // A) Try: base64 -> utf8 PEM text
  try {
    const decodedText = Buffer.from(raw, "base64").toString("utf8").trim();
    const maybePem = normalizePem(decodedText);
    if (maybePem.includes("BEGIN CERTIFICATE")) {
      return maybePem;
    }

    // If decoded text is just the cert-body base64, wrap it
    if (isBase64Like(decodedText)) {
      return normalizePem(wrapCertBodyToPem(decodedText));
    }
  } catch {
    // ignore and try DER path
  }

  // B) Try: base64 -> DER buffer -> convert to PEM using crypto
  try {
    const derBuf = Buffer.from(raw, "base64");
    const x = new crypto.X509Certificate(derBuf);
    return normalizePem(x.toString()); // PEM
  } catch {
    // ignore and try cert-body wrap
  }

  // C) Last try: treat raw itself as cert body and wrap
  if (isBase64Like(raw)) {
    return normalizePem(wrapCertBodyToPem(raw));
  }

  return "";
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

function asArray(v) {
  if (!v) return [];
  if (Array.isArray(v)) return v.filter(Boolean);
  if (typeof v === "string") return v ? [v] : [];
  return [];
}

function pickGroups(profile) {
  const g =
    profile.groups ||
    profile["http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"];
  return asArray(g);
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

/**
 * ✅ EXPORT THIS
 */
export async function initSamlStrategy() {
  const SAML_CALLBACK_URL = (process.env.SAML_CALLBACK_URL || "").trim();
  const SAML_ISSUER = (process.env.SAML_ISSUER || "").trim();
  const OKTA_SIGNON_URL = (process.env.OKTA_SIGNON_URL || "").trim();

  const OKTA_X509_CERT_PEM = (process.env.OKTA_X509_CERT_PEM || "").trim();
  const OKTA_X509_CERT_B64 = (process.env.OKTA_X509_CERT_B64 || "").trim();
  const OKTA_METADATA_URL = (process.env.OKTA_METADATA_URL || "").trim();

  if (!SAML_CALLBACK_URL) throw new Error("❌ Missing env: SAML_CALLBACK_URL");
  if (!SAML_ISSUER) throw new Error("❌ Missing env: SAML_ISSUER");
  if (!OKTA_SIGNON_URL) throw new Error("❌ Missing env: OKTA_SIGNON_URL");

  slog("ENV SUMMARY", {
    node: process.version,
    NODE_ENV: process.env.NODE_ENV,
    SAML_CALLBACK_URL,
    SAML_ISSUER,
    OKTA_SIGNON_URL,
    OKTA_X509_CERT_PEM: OKTA_X509_CERT_PEM ? "[set]" : "[missing]",
    OKTA_X509_CERT_B64: OKTA_X509_CERT_B64 ? "[set]" : "[missing]",
    OKTA_METADATA_URL: OKTA_METADATA_URL ? "[set]" : "[missing]",
  });

  let certPem = "";
  let source = "";

  if (OKTA_X509_CERT_PEM) {
    source = "OKTA_X509_CERT_PEM";
    certPem = normalizePem(OKTA_X509_CERT_PEM);
  } else if (OKTA_METADATA_URL) {
    source = "OKTA_METADATA_URL";
    certPem = await loadOktaCertFromMetadata(OKTA_METADATA_URL);
  } else if (OKTA_X509_CERT_B64) {
    source = "OKTA_X509_CERT_B64";
    certPem = pemFromOktaB64(OKTA_X509_CERT_B64);
  } else {
    throw new Error(
      "❌ Missing cert source. Set ONE of: OKTA_X509_CERT_PEM OR OKTA_METADATA_URL OR OKTA_X509_CERT_B64"
    );
  }

  slog("CERT SOURCE", source);

  if (
    !certPem ||
    !certPem.includes("-----BEGIN CERTIFICATE-----") ||
    !certPem.includes("-----END CERTIFICATE-----")
  ) {
    const preview = (certPem || "").slice(0, 60).replace(/\n/g, "\\n");
    throw new Error(
      `❌ OKTA cert is not valid PEM after processing. source=${source} preview="${preview}..."`
    );
  }

  const certCheck = inspectCertPem(certPem);
  if (!certCheck.ok) {
    throw new Error(
      `❌ Cert cannot be parsed under Node/OpenSSL in Azure. ${
        certCheck.error?.message || ""
      }`.trim()
    );
  }

  passport.serializeUser((user, done) => done(null, user));
  passport.deserializeUser((user, done) => done(null, user));

  passport.use(
    "saml",
    new SamlStrategy(
      {
        callbackUrl: SAML_CALLBACK_URL,
        entryPoint: OKTA_SIGNON_URL,
        issuer: SAML_ISSUER,

        // ✅ Signing certificate PEM
        cert: certCheck.pem,

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

          slog("PROFILE (SAFE)", {
            hasProfile: !!profile,
            keys: Object.keys(profile || {}).slice(0, 25),
            emailFound: !!email,
            groupsCount: groups.length,
            nameID: profile?.nameID ? "[set]" : "[missing]",
          });

          return done(null, {
            email,
            name: pickName(profile),
            groups,
            roles: groups,
            user_type: "internal",
            nameID: profile?.nameID || null,
          });
        } catch (err) {
          return done(err);
        }
      }
    )
  );

  slog("STRATEGY REGISTERED", {
    strategies: Object.keys(passport?._strategies || {}),
  });
}

export default passport;
