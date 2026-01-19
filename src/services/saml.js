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
 *  1) OKTA_X509_CERT_PEM  (raw PEM text, multi-line)
 *  2) OKTA_X509_CERT_B64  (single-line base64 of PEM text -> best for DevOps Var Group)
 *  3) OKTA_METADATA_URL   (fetch metadata and extract signing cert)
 *
 * Required:
 *  SAML_CALLBACK_URL, SAML_ISSUER, OKTA_SIGNON_URL
 */

const DEBUG_SAML = true;

function slog(label, obj) {
  if (!DEBUG_SAML) return;
  const ts = new Date().toISOString();
  if (obj !== undefined) console.log(`🧩 [SAML INIT] ${ts} ${label}`, obj);
  else console.log(`🧩 [SAML INIT] ${ts} ${label}`);
}

function safeErr(e) {
  return {
    message: e?.message || String(e),
    name: e?.name,
    code: e?.code,
    stackTop: (e?.stack || "").split("\n").slice(0, 6).join("\n"),
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

function isBase64Like(v) {
  const s = String(v || "").replace(/\s+/g, "");
  if (s.length < 100) return false;
  return /^[A-Za-z0-9+/=]+$/.test(s);
}

function wrapCertBodyToPem(certBodyB64) {
  const body = String(certBodyB64 || "").replace(/\s+/g, "");
  const lines = body.match(/.{1,64}/g)?.join("\n") || body;
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----`;
}

/**
 * OKTA_X509_CERT_B64 may be:
 *  - base64(PEM text)
 *  - base64(DER/binary)
 *  - base64(cert-body only)
 */
function pemFromOktaB64(b64Value) {
  const raw = stripWrappingQuotes(b64Value).replace(/\s+/g, "");
  if (!raw) return "";

  // A) base64 -> utf8 PEM text
  try {
    const decodedText = Buffer.from(raw, "base64").toString("utf8").trim();
    const maybePem = normalizePem(decodedText);
    if (maybePem.includes("BEGIN CERTIFICATE")) return maybePem;

    if (isBase64Like(decodedText))
      return normalizePem(wrapCertBodyToPem(decodedText));
  } catch {
    // ignore
  }

  // B) base64 -> DER buffer -> X509 -> PEM
  try {
    const derBuf = Buffer.from(raw, "base64");
    const x = new crypto.X509Certificate(derBuf);
    return normalizePem(x.toString());
  } catch {
    // ignore
  }

  // C) treat raw as cert-body
  if (isBase64Like(raw)) return normalizePem(wrapCertBodyToPem(raw));

  return "";
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

/** HTTPS GET with status + headers + redirect support (safe logs) */
function httpGetWithMeta(url, depth = 0) {
  return new Promise((resolve, reject) => {
    if (depth > 3)
      return reject(new Error("Too many redirects fetching metadata"));

    const req = https.get(
      url,
      { headers: { Accept: "application/xml,text/xml,*/*" } },
      (res) => {
        const { statusCode, headers } = res;
        let data = "";

        res.on("data", (c) => (data += c));
        res.on("end", async () => {
          // Follow redirects
          if (
            [301, 302, 303, 307, 308].includes(statusCode) &&
            headers?.location
          ) {
            const nextUrl = headers.location.startsWith("http")
              ? headers.location
              : new URL(headers.location, url).toString();

            slog("OKTA METADATA REDIRECT", {
              from: url,
              to: nextUrl,
              statusCode,
            });
            try {
              const next = await httpGetWithMeta(nextUrl, depth + 1);
              return resolve(next);
            } catch (e) {
              return reject(e);
            }
          }

          resolve({
            url,
            statusCode,
            contentType: headers?.["content-type"],
            body: data,
          });
        });
      }
    );

    req.on("error", reject);
  });
}

/** Recursively find any X509Certificate value in parsed xml2js object (namespace-safe) */
function findFirstX509CertificateNode(obj) {
  if (!obj || typeof obj !== "object") return null;

  for (const [k, v] of Object.entries(obj)) {
    // Matches: X509Certificate, ds:X509Certificate, anything ending with :X509Certificate
    if (k === "X509Certificate" || k.endsWith(":X509Certificate")) {
      const val = Array.isArray(v) ? v[0] : v;
      if (typeof val === "string" && val.trim()) return val.trim();
    }

    // Recurse arrays/objects
    if (Array.isArray(v)) {
      for (const item of v) {
        const found = findFirstX509CertificateNode(item);
        if (found) return found;
      }
    } else if (typeof v === "object") {
      const found = findFirstX509CertificateNode(v);
      if (found) return found;
    }
  }

  return null;
}

async function loadOktaCertFromMetadata(metadataUrl) {
  const resp = await httpGetWithMeta(metadataUrl);

  slog("OKTA METADATA FETCH", {
    url: resp.url,
    statusCode: resp.statusCode,
    contentType: resp.contentType,
    bodyStartsWith: String(resp.body || "")
      .slice(0, 80)
      .replace(/\s+/g, " "),
  });

  if (resp.statusCode !== 200) {
    throw new Error(
      `Okta metadata fetch failed with status ${resp.statusCode}`
    );
  }

  // If Okta returns HTML/login page, fail with a clear message
  const bodyTrim = String(resp.body || "").trim();
  if (bodyTrim.startsWith("<!DOCTYPE html") || bodyTrim.startsWith("<html")) {
    throw new Error(
      "Okta metadata URL returned HTML (not XML). Check metadata URL / access."
    );
  }

  const parsed = await parseStringPromise(resp.body);

  // Try strict known path first (keeps behavior when structure matches)
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

  // If strict path fails, do a deep search (handles namespaces/shape changes)
  if (!certB64) {
    const deep = findFirstX509CertificateNode(parsed);
    if (deep) certB64 = String(deep).replace(/\s+/g, "");
  }

  if (!certB64) {
    throw new Error("❌ Could not extract X509Certificate from Okta metadata");
  }

  return wrapCertBodyToPem(certB64);
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

  // ✅ Priority: PEM -> B64 -> METADATA (best for DevOps)
  if (OKTA_X509_CERT_PEM) {
    source = "OKTA_X509_CERT_PEM";
    certPem = normalizePem(OKTA_X509_CERT_PEM);
  } else if (OKTA_X509_CERT_B64) {
    source = "OKTA_X509_CERT_B64";
    certPem = pemFromOktaB64(OKTA_X509_CERT_B64);
  } else if (OKTA_METADATA_URL) {
    source = "OKTA_METADATA_URL";
    certPem = await loadOktaCertFromMetadata(OKTA_METADATA_URL);
  } else {
    throw new Error(
      "❌ Missing cert source. Set ONE of: OKTA_X509_CERT_PEM OR OKTA_X509_CERT_B64 OR OKTA_METADATA_URL"
    );
  }

  // ✅ If metadata is configured but fails, fallback to B64 (prevents outages)
  if (
    source === "OKTA_METADATA_URL" &&
    (!certPem || !certPem.includes("BEGIN CERTIFICATE"))
  ) {
    if (OKTA_X509_CERT_B64) {
      slog("METADATA FAILED → FALLBACK TO OKTA_X509_CERT_B64");
      source = "OKTA_X509_CERT_B64";
      certPem = pemFromOktaB64(OKTA_X509_CERT_B64);
    }
  }

  slog("CERT SOURCE", source);

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
