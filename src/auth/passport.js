import passport from "passport";
import { Strategy as SamlStrategy } from "passport-saml";
import https from "https";
import { parseStringPromise } from "xml2js";

/**
 * Minimal XML parser (no extra libs besides xml2js)
 * If you don't have xml2js:
 *   npm i xml2js
 */

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
  const xml = await httpGet(metadataUrl);
  const parsed = await parseStringPromise(xml);

  // Try to locate the X509Certificate node in common Okta metadata structure
  const entity = parsed?.EntityDescriptor;
  const idp = entity?.IDPSSODescriptor?.[0];
  const keyDescriptors = idp?.KeyDescriptor || [];

  // Prefer "signing" usage if present
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

export async function initPassport() {
  const SAML_CALLBACK_URL = (process.env.SAML_CALLBACK_URL || "").trim();
  const OKTA_SSO_URL = (process.env.OKTA_SSO_URL || "").trim();
  const SAML_ISSUER = (process.env.SAML_ISSUER || "").trim();

  // ✅ New env (already in your Azure): OKTA_METADATA_URL
  const OKTA_METADATA_URL = (process.env.OKTA_METADATA_URL || "").trim();

  if (!SAML_CALLBACK_URL) throw new Error("❌ Missing env: SAML_CALLBACK_URL");
  if (!OKTA_SSO_URL) throw new Error("❌ Missing env: OKTA_SSO_URL");
  if (!SAML_ISSUER) throw new Error("❌ Missing env: SAML_ISSUER");
  if (!OKTA_METADATA_URL) throw new Error("❌ Missing env: OKTA_METADATA_URL");

  // ✅ Always pull the right cert from Okta directly
  const oktaPemCert = await loadOktaCertFromMetadata(OKTA_METADATA_URL);

  passport.use(
    new SamlStrategy(
      {
        callbackUrl: SAML_CALLBACK_URL,
        entryPoint: OKTA_SSO_URL,
        issuer: SAML_ISSUER,
        cert: oktaPemCert,
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

  console.log("✅ Okta SAML strategy initialized (cert loaded from metadata)");
}

export default passport;
