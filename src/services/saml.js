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
 *  1) OKTA_X509_CERT_PEM  (raw PEM; can be multi-line or "\n" escaped)
 *  2) OKTA_X509_CERT_B64  (single-line base64; can be:
 *        a) base64 of PEM text (preferred)
 *        b) base64 of the raw cert body
 *        c) base64 of DER/binary cert
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

  if (!certB64) {
    throw new Error("❌ Could not extract X509Certificate from Okta metadata");
  }

  return wrapCertBodyToPem(certB64);
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

  // Convert literal \n to newlines (Azure App Settings often store it like this)
  v = v.replace(/\\n/g, "\n").trim();

  // Remove BOM if any
  v = v.replace(/^\uFEFF/, "");

  // Ensure BEGIN/END lines are on their own lines
  if (v.includes("-----BEGIN CERTIFICATE-----") && !v.includes("\n")) {
    v = v
      .replace("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n")
      .replace("-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----");
  }

  return v.trim();
}

function wrapCertBodyToPem(certBodyB64) {
  const body = String(certBodyB64 || "").replace(/\s+/g, "");
  const lines = body.match(/.{1,64}/g)?.join("\n") || body;
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----`;
}

function isProbablyBase64(s) {
  const v = String(s || "").trim();
  if (v.length < 100) return false;
  // allow newlines/spaces (we strip them)
  const cleaned = v.replace(/\s+/g, "");
  // basic base64 charset check
  return /^[A-Za-z0-9+/=]+$/.test(cleaned);
}

function tryParseAsPem(pem) {
  const normalized = normalizePem(pem);
  if (
    normalized.includes("-----BEGIN CERTIFICATE-----") &&
    normalized.includes("-----END CERTIFICATE-----")
  ) {
    return normalized;
  }
  return null;
}

function tryDerBase64ToPem(b64) {
  // If the base64 is DER (binary), we can convert to PEM using crypto.X509Certificate
  const cleaned = String(b64 || "").replace(/\s+/g, "");
  const der = Buffer.from(cleaned, "base64");
  try {
    const x = new crypto.X509Certificate(der);
    // Node returns a PEM string here
    const pem = x.toString();
    return normalizePem(pem);
  } catch {
    return null;
  }
}

function pemFromB64Flexible(b64) {
  const raw = stripWrappingQuotes(b64).replace(/\s+/g, "");

  // 1) Decode as utf8 text (most common: base64(PEM text))
  let decodedUtf8 = "";
  try {
    decodedUtf8 = Buffer.from(raw, "base64").toString("utf8").trim();
  } catch {
    decodedUtf8 = "";
  }

  // 1a) If decoded text is PEM, done
  const pemFromDecoded = tryParseAsPem(decodedUtf8);
  if (pemFromDecoded) return pemFromDecoded;

  // 1b) If decoded text looks like "just cert body" base64, wrap it
  if (decodedUtf8 && isProbablyBase64(decodedUtf8)) {
    const wrapped = wrapCertBodyToPem(decodedUtf8);
    const asPem = tryParseAsPem(wrapped);
    if (asPem) return asPem;
  }

  // 2) If original env var is actually "just cert body" base64, wrap it
  if (isProbablyBase64(raw)) {
    const wrapped = wrapCertBodyToPem(raw);
    // validate quickly by trying crypto parse
    const ok = inspectCertPem(wrapped).ok;
    if (ok) return normalizePem(wrapped);
  }

  // 3) If it is DER base64 (binary), convert DER->PEM
  const derPem = tryDerBase64ToPem(raw);
  if (derPem) return derPem;

  // 4) Last resort: return decodedUtf8 (may help diagnose)
  return normalizePem(decodedUtf8 || "");
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
  let certSource = "";

  if (OKTA_X509_CERT_PEM) {
    certPem = normalizePem(OKTA_X509_CERT_PEM);
    certSource = "OKTA_X509_CERT_PEM";
  } else if (OKTA_X509_CERT_B64) {
    // ✅ Flexible: supports base64(PEM text) OR base64(cert body) OR DER base64
    certPem = pemFromB64Flexible(OKTA_X509_CERT_B64);
    certSource = "OKTA_X509_CERT_B64";
  } else if (OKTA_METADATA_URL) {
    certPem = await loadOktaCertFromMetadata(OKTA_METADATA_URL);
    certSource = "OKTA_METADATA_URL";
  } else {
    throw new Error(
      "❌ Missing cert source. Set ONE of: OKTA_X509_CERT_PEM OR OKTA_X509_CERT_B64 OR OKTA_METADATA_URL"
    );
  }

  slog("CERT SOURCE", certSource);

  // ✅ Final sanity check: must look like PEM
  const pemLooksValid =
    certPem.includes("-----BEGIN CERTIFICATE-----") &&
    certPem.includes("-----END CERTIFICATE-----");

  if (!pemLooksValid) {
    const preview = (certPem || "").slice(0, 50).replace(/\n/g, "\\n");
    throw new Error(
      `❌ OKTA cert is not PEM after normalization. Source=${certSource} preview="${preview}..."`
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

        // ✅ Signing cert (PEM)
        cert: certCheck.pem,

        identifierFormat: null,
        wantAssertionsSigned: true,
        wantAuthnResponseSigned: true,

        // Stability behind proxies / multi-instance
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
