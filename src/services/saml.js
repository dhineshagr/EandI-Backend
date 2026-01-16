// src/services/saml.js
import dotenv from "dotenv";
dotenv.config();

import passport from "passport";
import { Strategy as SamlStrategy } from "passport-saml";
import https from "https";
import { parseStringPromise } from "xml2js";

/* ---------------- Logging ---------------- */
const DEBUG_SAML =
  String(process.env.DEBUG_SAML || "true").toLowerCase() === "true";
function dbg(label, obj) {
  if (!DEBUG_SAML) return;
  console.log(`🧩 [SAML DEBUG] ${label}`, obj || "");
}

/* ---------------- Helpers ---------------- */
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
  dbg("Fetching Okta metadata", { metadataUrl });

  const xml = await httpGet(metadataUrl);

  dbg("Okta metadata fetched", {
    xmlLen: xml.length,
    hasEntityDescriptor: xml.includes("EntityDescriptor"),
    hasX509: xml.includes("X509Certificate"),
  });

  const parsed = await parseStringPromise(xml, {
    explicitArray: true,
    ignoreAttrs: false,
    trim: true,
  });

  const entity = parsed?.EntityDescriptor;
  const idp = entity?.IDPSSODescriptor?.[0];
  const keyDescriptors = idp?.KeyDescriptor || [];

  let certB64 = null;

  for (const kd of keyDescriptors) {
    const use = kd?.$?.use; // signing | encryption | undefined
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
  const pem = `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----`;

  dbg("Extracted signing cert from metadata (safe)", {
    pemStartsWith: pem.split("\n")[0],
    pemLen: pem.length,
  });

  return pem;
}

/* ---------------- Init Passport ---------------- */
export async function initPassport() {
  const SAML_CALLBACK_URL = (process.env.SAML_CALLBACK_URL || "").trim();
  const SAML_ISSUER = (process.env.SAML_ISSUER || "").trim();

  // ✅ Use ONE name consistently. Prefer OKTA_SIGNON_URL (matches your Azure)
  const OKTA_SIGNON_URL = (
    process.env.OKTA_SIGNON_URL ||
    process.env.OKTA_SSO_URL ||
    ""
  ).trim();

  const OKTA_METADATA_URL = (process.env.OKTA_METADATA_URL || "").trim();

  if (!SAML_CALLBACK_URL) throw new Error("❌ Missing env: SAML_CALLBACK_URL");
  if (!SAML_ISSUER) throw new Error("❌ Missing env: SAML_ISSUER");
  if (!OKTA_SIGNON_URL)
    throw new Error("❌ Missing env: OKTA_SIGNON_URL (or OKTA_SSO_URL)");
  if (!OKTA_METADATA_URL) throw new Error("❌ Missing env: OKTA_METADATA_URL");

  dbg("SAML ENV (safe)", {
    SAML_CALLBACK_URL,
    SAML_ISSUER,
    OKTA_SIGNON_URL,
    oktaMetadataHost: (() => {
      try {
        return new URL(OKTA_METADATA_URL).host;
      } catch {
        return "invalid-url";
      }
    })(),
  });

  const oktaPemCert = await loadOktaCertFromMetadata(OKTA_METADATA_URL);

  passport.use(
    new SamlStrategy(
      {
        callbackUrl: SAML_CALLBACK_URL,
        entryPoint: OKTA_SIGNON_URL,
        issuer: SAML_ISSUER,

        // ✅ cert can be string or array
        cert: [oktaPemCert],

        wantAssertionsSigned: true,
        wantAuthnResponseSigned: true,
        identifierFormat: null,

        // Proxy/time skew helpers (Azure)
        validateInResponseTo: false,
        acceptedClockSkewMs: 5 * 60 * 1000,
      },
      (profile, done) => {
        try {
          dbg("SAML profile received (safe)", {
            keys: profile ? Object.keys(profile) : [],
            nameID: profile?.nameID
              ? String(profile.nameID).slice(0, 8) + "***"
              : null,
            groupsCount: pickGroups(profile).length,
            hasEmail: !!pickEmail(profile),
          });

          return done(null, {
            email: pickEmail(profile),
            name: pickName(profile),
            groups: pickGroups(profile),
            okta_id: profile?.nameID || null,
            user_type: "internal",
          });
        } catch (err) {
          return done(err);
        }
      }
    )
  );

  passport.serializeUser((user, done) => done(null, user));
  passport.deserializeUser((user, done) => done(null, user));

  console.log("✅ Okta SAML strategy initialized (cert loaded from metadata)");
}

export default passport;
