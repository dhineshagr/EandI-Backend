// src/auth/passport.js
import passport from "passport";
import { Strategy as SamlStrategy } from "passport-saml";

export function initPassport() {
  passport.use(
    new SamlStrategy(
      {
        callbackUrl: process.env.SAML_CALLBACK_URL,
        entryPoint: process.env.OKTA_SSO_URL, // Signon URL
        issuer: process.env.SAML_ISSUER,
        cert: process.env.OKTA_X509_CERT, // 🔑 X.509 cert from Okta
        wantAssertionsSigned: true,
        wantAuthnResponseSigned: true,
        identifierFormat: null,
      },
      (profile, done) => {
        /**
         * This profile comes FROM OKTA
         */
        return done(null, {
          email:
            profile.email ||
            profile[
              "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
            ],
          name:
            profile.displayName || profile.firstName + " " + profile.lastName,
          groups: profile.groups || [],
          okta_id: profile.nameID,
        });
      }
    )
  );

  passport.serializeUser((user, done) => done(null, user));
  passport.deserializeUser((user, done) => done(null, user));
}

export default passport;
