// src/services/saml.js
import dotenv from "dotenv";
dotenv.config();

import passport from "passport";
import { Strategy as SamlStrategy } from "passport-saml";
import crypto from "crypto";
import https from "https";
import { parseStringPromise } from "xml2js";

/**
 * Cert sources supported (in priority order):
 *  1) OKTA_X509_CERT_PEM  (raw PEM, multi-line; best for Azure App Settings UI)
 *  2) OKTA_X509_CERT_B64  (single-line base64 of PEM; best for Azure DevOps Variable Group)
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

  if (!certB64)
    throw new Error("❌ Could not extract X509Certificate from Okta metadata");

  const lines = certB64.match(/.{1,64}/g)?.join("\n") || certB64;
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----`;
}

function normalizePem(pem) {
  let v = String(pem || "").trim();

  // remove wrapping quotes if something added them
  if (
    (v.startsWith('"') && v.endsWith('"')) ||
    (v.startsWith("'") && v.endsWith("'"))
  ) {
    v = v.slice(1, -1).trim();
  }

  // Convert literal \n to newlines
  v = v.replace(/\\n/g, "\n").trim();

  // Ensure proper line breaks if someone stored BEGIN/END with no newlines
  if (v.includes("-----BEGIN CERTIFICATE-----") && !v.includes("\n")) {
    v = v
      .replace("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n")
      .replace("-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----");
  }

  return v;
}

function pemFromB64(b64) {
  let v = String(b64 || "").trim();

  // remove wrapping quotes
  if (
    (v.startsWith('"') && v.endsWith('"')) ||
    (v.startsWith("'") && v.endsWith("'"))
  ) {
    v = v.slice(1, -1).trim();
  }

  // remove whitespace/newlines in the base64 string itself
  v = v.replace(/\s+/g, "");

  const decoded = Buffer.from(v, "base64").toString("utf8");
  return normalizePem(decoded);
}

function inspectCertPem(pem) {
  const normalized = normalizePem(pem);

  const lines = normalized.split("\n").filter(Boolean);
  slog("CERT STRING (SAFE)", {
    firstLine: lines[0],
    lastLine: lines[lines.length - 1],
    length: normalized.length,
    lines: lines.length,
  });

  // Validate parse under current OpenSSL (helps catch bad base64/format)
  try {
    // Node expects a valid PEM here; if not, it throws
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
 * ✅ EXPORT THIS (so server.js can call it explicitly)
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

  if (OKTA_X509_CERT_PEM) {
    certPem = normalizePem(OKTA_X509_CERT_PEM);
    slog("CERT SOURCE", "OKTA_X509_CERT_PEM");
  } else if (OKTA_X509_CERT_B64) {
    certPem = pemFromB64(OKTA_X509_CERT_B64);
    slog("CERT SOURCE", "OKTA_X509_CERT_B64");
  } else if (OKTA_METADATA_URL) {
    certPem = await loadOktaCertFromMetadata(OKTA_METADATA_URL);
    slog("CERT SOURCE", "OKTA_METADATA_URL");
  } else {
    throw new Error(
      "❌ Missing cert source. Set ONE of: OKTA_X509_CERT_PEM OR OKTA_X509_CERT_B64 OR OKTA_METADATA_URL"
    );
  }

  const certCheck = inspectCertPem(certPem);
  if (!certCheck.ok) {
    // This is the exact Azure error you saw: bad base64 decode
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

        // ✅ signing cert (NOT encryption cert)
        cert: certCheck.pem,

        identifierFormat: null,
        wantAssertionsSigned: true,
        wantAuthnResponseSigned: true,

        // Stability behind proxies
        validateInResponseTo: false,
        acceptedClockSkewMs: 5 * 60 * 1000,
        requestIdExpirationPeriodMs: 5 * 60 * 1000,
      },
      (profile, done) => {
        try {
          const email = pickEmail(profile);
          const groups = pickGroups(profile);

          // Safe profile diagnostics (no dump)
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
