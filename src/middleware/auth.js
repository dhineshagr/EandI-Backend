import jwt from "jsonwebtoken";
import createError from "http-errors";
import jwksClient from "jwks-rsa";
import { query } from "../db.js";
import bcrypt from "bcryptjs";

/* ------------------------------------------------------------------
   Config
------------------------------------------------------------------ */
const jwtSecret = process.env.JWT_SECRET || "dev-secret";

const tenantId =
  process.env.AZURE_TENANT_ID || "62aed837-f528-4768-9913-ab94d9064b3e";

const audience =
  process.env.AZURE_API_AUDIENCE ||
  "api://e5614425-4dbe-4f35-b725-64b9a2b92827";

const issuers = [
  `https://sts.windows.net/${tenantId}/`,
  `https://login.microsoftonline.com/${tenantId}/v2.0`,
];

const client = jwksClient({
  jwksUri: `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`,
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, function (err, key) {
    if (err) {
      console.error("JWKS key fetch error:", err);
      return callback(err, null);
    }
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

/* ------------------------------------------------------------------
   Helpers
------------------------------------------------------------------ */
function getTokenFromHeader(req) {
  const hdr = req.headers.authorization || "";
  return hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
}

function dbUserToReqUser(row) {
  return {
    typ: "internal",
    user_id: row.user_id,
    username: row.username,
    email: row.email,
    role: row.role,
    user_type: row.user_type,
    bp_code: row.bp_code || null,
    okta_id: row.okta_id || null,
    is_active: row.is_active,
    roles: row.role ? [row.role] : [],
    name: row.display_name || row.username || row.email,
  };
}

function mergeRoles(a = [], b = []) {
  const set = new Set([...(a || []), ...(b || [])].filter(Boolean));
  return Array.from(set);
}

/* ------------------------------------------------------------------
   BP Auth (Business Partner)
------------------------------------------------------------------ */
export function issueBpToken(payload) {
  return jwt.sign(payload, jwtSecret, {
    expiresIn: process.env.JWT_EXPIRES_IN || "8h",
  });
}

export async function bpLogin(username, password) {
  const { rows } = await query(
    `SELECT bp_user_id, username, email, password_hash, bp_code, is_active
     FROM eandi.users_bp
     WHERE username=@p1`,
    [username]
  );

  if (rows.length === 0) throw createError(401, "Invalid credentials");
  const u = rows[0];
  if (!u.is_active) throw createError(403, "User disabled");

  const ok = await bcrypt.compare(password, u.password_hash);
  if (!ok) throw createError(401, "Invalid credentials");

  const token = issueBpToken({
    sub: `bp:${u.bp_user_id}`,
    typ: "bp",
    username: u.username,
    email: u.email,
    bp_code: u.bp_code,
    roles: ["uploader"],
  });

  return {
    token,
    profile: {
      bp_user_id: u.bp_user_id,
      email: u.email,
      username: u.username,
      bp_code: u.bp_code,
    },
  };
}

export function requireBpAuth(req, _res, next) {
  try {
    const token = getTokenFromHeader(req);
    if (!token) throw createError(401, "Missing token");

    const decoded = jwt.verify(token, jwtSecret);
    if (decoded.typ !== "bp") throw createError(401, "Invalid token type");

    req.user = {
      typ: "bp",
      bp_user_id: decoded.sub?.replace(/^bp:/, "") || undefined,
      username: decoded.username,
      email: decoded.email,
      bp_code: decoded.bp_code,
      role: "Business Partner",
      roles: mergeRoles(["Business Partner"], decoded.roles),
      is_active: true,
      name: decoded.username || decoded.email,
      user_type: "bp",
    };
    next();
  } catch (err) {
    next(createError(401, err.message || "Unauthorized"));
  }
}

/* ------------------------------------------------------------------
   Internal (Azure AD / Entra ID) Auth
------------------------------------------------------------------ */
function verifyAzureToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(
      token,
      getKey,
      { audience, algorithms: ["RS256"] },
      (err, decoded) => {
        if (err)
          return reject(createError(401, err.message || "Invalid token"));
        if (!issuers.includes(decoded.iss)) {
          return reject(createError(401, "Invalid issuer"));
        }
        resolve(decoded);
      }
    );
  });
}

/** ✅ Require Internal Auth (supports HS256 local + RS256 Azure) */
export async function requireInternalAuth(req, _res, next) {
  try {
    // ✅ Build safe URL object (no crash if missing host/proto)
    try {
      const proto = req.protocol || "http";
      const host = req.get?.("host") || "localhost";
      const orig = req.originalUrl || "/";
      req.safeUrl = new URL(`${proto}://${host}${orig}`);
    } catch {
      req.safeUrl = { searchParams: new URLSearchParams() };
    }

    const token = getTokenFromHeader(req);
    console.log("🔎 Incoming Authorization header:", req.headers.authorization);
    if (!token) throw createError(401, "Missing token");

    const decodedHeader = jwt.decode(token, { complete: true })?.header;

    // ✅ Case 1: HS256 (local dev)
    if (decodedHeader?.alg === "HS256") {
      const decodedLocal = jwt.verify(token, jwtSecret);
      req.user = {
        typ: decodedLocal.user_type,
        email: decodedLocal.email,
        role: decodedLocal.role,
        username: decodedLocal.email,
        fullName: decodedLocal.name,
        user_type: decodedLocal.user_type,
        roles: [decodedLocal.role],
      };
      console.log("✅ Verified local HS256 token:", req.user);
      return next();
    }

    // ✅ Case 2: RS256 (Azure AD token)
    const decoded = await verifyAzureToken(token);
    const email = (
      decoded.preferred_username ||
      decoded.upn ||
      decoded.email ||
      ""
    )
      .toLowerCase()
      .trim();
    if (!email) throw createError(401, "Email claim missing in token");

    // ✅ Fixed for SQL Server — use TOP 1 (no LIMIT)
    const { rows } = await query(
      `SELECT TOP 1 user_id, user_type, username, display_name, email, bp_code, okta_id, role, is_active
       FROM users
       WHERE LOWER(email) = LOWER(@p1);`,
      [email]
    );

    if (rows.length === 0) throw createError(403, "User not provisioned");
    const row = rows[0];
    if (!row.is_active) throw createError(403, "User disabled");

    const normalized = dbUserToReqUser(row);
    normalized.roles = mergeRoles(normalized.roles, decoded.roles || []);
    if (!normalized.name) normalized.name = decoded.name || normalized.email;

    req.user = normalized;

    console.log("✅ Decoded Azure AD token + DB user:", {
      aud: decoded.aud,
      iss: decoded.iss,
      token_roles: decoded.roles,
      db_role: row.role,
      req_user: req.user,
    });

    next();
  } catch (err) {
    console.error("❌ requireInternalAuth error:", err.message);
    next(createError(err.status || 401, err.message || "Unauthorized"));
  }
}

/* ------------------------------------------------------------------
   Unified guard
------------------------------------------------------------------ */
export async function requireAuth(req, res, next) {
  try {
    await new Promise((resolve, reject) =>
      requireInternalAuth(req, res, (err) => (err ? reject(err) : resolve()))
    );
    return next();
  } catch {
    try {
      requireBpAuth(req, res, (err) => {
        if (err) throw err;
        return next();
      });
    } catch (err2) {
      return next(
        createError(err2.status || 401, err2.message || "Unauthorized")
      );
    }
  }
}

/* ------------------------------------------------------------------
   ✅ Unified Export (fix for uploads.js import)
------------------------------------------------------------------ */
export const authenticateToken = requireAuth;

/* ------------------------------------------------------------------
   ✅ Helper Fix for Downstream Routes Using searchParams
------------------------------------------------------------------ */
export function safeParseUrl(req) {
  try {
    const proto = req.protocol || "http";
    const host = req.get?.("host") || "localhost";
    const orig = req.originalUrl || "/";
    return new URL(`${proto}://${host}${orig}`);
  } catch (err) {
    console.error("safeParseUrl error:", err.message);
    return { searchParams: new URLSearchParams() };
  }
}
