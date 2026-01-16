// src/services/saml.js
import dotenv from "dotenv";
dotenv.config();

import passport from "passport";
import { Strategy as SamlStrategy } from "passport-saml";
import https from "https";
import { parseStringPromise } from "xml2js";

/* ------------------------------------------------------
   Required Environment Variables
------------------------------------------------------ */
const SAML_CALLBACK_URL = (process.env.SAML_CALLBACK_URL || "").trim();
const SAML_ISSUER = (process.env.SAML_ISSUER || "").trim();
const OKTA_SIGNON_URL = (process.env.OKTA_SIGNON_URL || "").trim();

const OKTA_X509_CERT_B64 = (process.env.OKTA_X509_CERT_B64 || "").trim(); // ✅
const OKTA_METADATA_URL = (process.env.OKTA_METADATA_URL || "").trim(); // optional fallback

/* ------------------------------------------------------
   Fail fast
------------------------------------------------------ */
if (!SAML_CALLBACK_URL) throw new Error("❌ Missing env: SAML_CALLBACK_URL");
if (!SAML_ISSUER) throw new Error("❌ Missing env: SAML_ISSUER");
if (!OKTA_SIGNON_URL) throw new Error("❌ Missing env: OKTA_SIGNON_URL");

if (!OKTA_X509_CERT_B64 && !OKTA_METADATA_URL) {
  throw new Error(
    "❌ Missing env: OKTA_X509_CERT_B64 (recommended) OR OKTA_METADATA_URL (fallback)"
  );
}

/* ------------------------------------------------------
   Helpers
------------------------------------------------------ */
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

function decodeOktaCertFromB64(b64) {
  let v = String(b64 || "").trim();

  // remove wrapping quotes if they exist
  if (
    (v.startsWith('"') && v.endsWith('"')) ||
    (v.startsWith("'") && v.endsWith("'"))
  ) {
    v = v.slice(1, -1).trim();
  }

  const pem = Buffer.from(v.replace(/\s+/g, ""), "base64")
    .toString("utf8")
    .replace(/\\n/g, "\n")
    .trim();

  if (!pem.includes("BEGIN CERTIFICATE")) {
    throw new Error("❌ OKTA_X509_CERT_B64 decoded value is not valid PEM");
  }

  return pem;
}

async function loadOktaSigningCertFromMetadata(metadataUrl) {
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

  const lines = certB64.match(/.{1,64}/g)?.join("\n") || certB64;
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
   Initialize Strategy
------------------------------------------------------ */
(async () => {
  try {
    let signingCertPem = "";

    if (OKTA_X509_CERT_B64) {
      signingCertPem = decodeOktaCertFromB64(OKTA_X509_CERT_B64);
      console.log("✅ Okta signing cert loaded from OKTA_X509_CERT_B64", {
        startsWith: signingCertPem.split("\n")[0],
        length: signingCertPem.length,
      });
    } else {
      signingCertPem = await loadOktaSigningCertFromMetadata(OKTA_METADATA_URL);
      console.log("✅ Okta signing cert loaded from OKTA_METADATA_URL", {
        startsWith: signingCertPem.split("\n")[0],
        length: signingCertPem.length,
      });
    }

    passport.use(
      new SamlStrategy(
        {
          callbackUrl: SAML_CALLBACK_URL,
          entryPoint: OKTA_SIGNON_URL,
          issuer: SAML_ISSUER,
          cert: signingCertPem,

          identifierFormat: null,
          wantAssertionsSigned: true,
          wantAuthnResponseSigned: true,

          // proxy/time skew helpers (Azure + Okta)
          validateInResponseTo: false,
          acceptedClockSkewMs: 5 * 60 * 1000,
          requestIdExpirationPeriodMs: 5 * 60 * 1000,
        },
        (profile, done) => {
          try {
            const email = pickEmail(profile);
            const groups = pickGroups(profile);

            return done(null, {
              email,
              name: pickName(profile),
              groups,
              roles: groups,
              user_type: "internal",
              nameID: profile.nameID,
            });
          } catch (err) {
            return done(err);
          }
        }
      )
    );

    console.log("✅ Okta SAML strategy initialized");
  } catch (e) {
    console.error("❌ Failed to init SAML strategy:", e?.message || e);
  }
})();

export default passport;
