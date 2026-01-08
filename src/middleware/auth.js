// src/middleware/auth.js
import jwt from "jsonwebtoken";
import createError from "http-errors";
import bcrypt from "bcryptjs";
import { query } from "../db.js";

const jwtSecret = process.env.JWT_SECRET || "dev-secret";

// ✅ Turn ON temporarily to see what's happening
const DEBUG_AUTHZ = true;

function dbg(label, obj) {
  if (!DEBUG_AUTHZ) return;
  console.log(`🧩 [AUTHZ DEBUG] ${label}`, obj);
}

function getTokenFromHeader(req) {
  const hdr = req.headers.authorization || "";
  return hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
}

function normalizeGroups(groups) {
  if (!groups) return [];
  if (Array.isArray(groups)) return groups.filter(Boolean).map(String);
  if (typeof groups === "string") return [groups];
  return [];
}

/**
 * ✅ Extract email from many possible SAML shapes
 */
function pickEmail(raw) {
  if (!raw) return "";

  const candidates = [
    raw.email,
    raw.mail,
    raw.upn,
    raw.nameID, // very common in SAML
    raw.username,
    raw.userPrincipalName,
    raw["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"],
    raw["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"],
    raw["emailaddress"],
  ].filter(Boolean);

  const found = candidates.find((v) => String(v).includes("@"));
  return (found ? String(found) : "").toLowerCase().trim();
}

function normalizeSessionUser(u) {
  if (!u) return null;

  const email = pickEmail(u);
  const groups = normalizeGroups(u.groups || u.roles || u.role);

  return {
    typ: "internal",
    user_type: "internal",

    user_id: u.user_id ?? null,
    username: u.username || u.name || null,
    email, // ✅ robust

    name: u.display_name || u.name || u.username || email,
    bp_code: u.bp_code || null,
    okta_id: u.okta_id || null,
    is_active: u.is_active ?? true,

    groups,
    roles: groups, // compatibility
    role: u.role || null,
  };
}

export function safeParseUrl(req) {
  try {
    return new URL(
      `${req.protocol || "http"}://${req.get("host")}${req.originalUrl}`
    );
  } catch {
    return { searchParams: new URLSearchParams() };
  }
}

/**
 * ✅ DB enrichment: try email first, if missing try username
 */
async function enrichInternalFromDb(rawUser) {
  const email = pickEmail(rawUser);
  const username = rawUser?.username ? String(rawUser.username).trim() : "";

  dbg("enrichInternalFromDb input", { email, username });

  if (email) {
    const byEmail = await query(
      `
      SELECT TOP 1 user_id, username, display_name, email, role, is_active
      FROM users
      WHERE LOWER(email)=LOWER(@p1) AND user_type='internal'
      ORDER BY updated_at DESC;
      `,
      [email]
    );
    if (byEmail.rows.length) return byEmail.rows[0];
  }

  if (username) {
    const byUser = await query(
      `
      SELECT TOP 1 user_id, username, display_name, email, role, is_active
      FROM users
      WHERE LOWER(username)=LOWER(@p1) AND user_type='internal'
      ORDER BY updated_at DESC;
      `,
      [username]
    );
    if (byUser.rows.length) return byUser.rows[0];
  }

  return null;
}

/* ---------------- BP AUTH (JWT) ---------------- */

export function issueBpToken(payload) {
  return jwt.sign(payload, jwtSecret, {
    expiresIn: process.env.JWT_EXPIRES_IN || "8h",
  });
}

export async function bpLogin(username, password) {
  const { rows } = await query(
    `
    SELECT bp_user_id, username, email, password_hash, bp_code, is_active
    FROM eandi.users_bp
    WHERE username=@p1
    `,
    [username]
  );

  if (!rows.length) throw createError(401, "Invalid credentials");
  if (!rows[0].is_active) throw createError(403, "User disabled");

  const ok = await bcrypt.compare(password, rows[0].password_hash);
  if (!ok) throw createError(401, "Invalid credentials");

  const token = issueBpToken({
    sub: `bp:${rows[0].bp_user_id}`,
    typ: "bp",
    username: rows[0].username,
    email: rows[0].email,
    bp_code: rows[0].bp_code,
    roles: ["Business Partner", "uploader"],
  });

  return {
    token,
    profile: {
      user_type: "bp",
      email: rows[0].email,
      username: rows[0].username,
      bp_code: rows[0].bp_code,
    },
  };
}

export function requireBpAuth(req, _res, next) {
  try {
    const token = getTokenFromHeader(req);
    if (!token) throw createError(401, "Missing token");

    const decoded = jwt.verify(token, jwtSecret);
    if (decoded.typ !== "bp") throw createError(401, "Invalid token");

    req.user = {
      typ: "bp",
      user_type: "bp",
      username: decoded.username,
      email: decoded.email,
      bp_code: decoded.bp_code,
      name: decoded.username || decoded.email,
      roles: normalizeGroups(decoded.roles),
      groups: normalizeGroups(decoded.roles),
      is_active: true,
    };

    return next();
  } catch (err) {
    return next(createError(401, err.message || "Unauthorized"));
  }
}

/* ---------------- INTERNAL AUTH (SESSION – OKTA SAML) ---------------- */
/**
 * ✅ FIX:
 * Passport/session can store user in multiple shapes:
 *   - req.session.user.user  (your current environment)
 *   - req.session.user       (older versions)
 *   - req.session.passport.user (passport default)
 */
function getRawSessionUser(req) {
  return (
    req.session?.user?.user ||
    req.session?.user ||
    req.session?.passport?.user ||
    null
  );
}

export async function requireSessionAuth(req, _res, next) {
  try {
    const raw = getRawSessionUser(req);
    if (!raw) throw createError(401, "Not authenticated");

    let user = normalizeSessionUser(raw);

    // ✅ DB enrichment by email OR username
    const dbRow = await enrichInternalFromDb(raw);

    dbg("session raw user keys", {
      keys: raw ? Object.keys(raw) : [],
      rawEmail: raw?.email,
      rawNameID: raw?.nameID,
      normalizedEmail: user.email,
    });

    if (dbRow) {
      if (!dbRow.is_active) throw createError(403, "User disabled");

      user = {
        ...user,
        user_id: dbRow.user_id,
        username: dbRow.username || user.username,
        name: dbRow.display_name || user.name,
        email: (dbRow.email || user.email || "").toLowerCase().trim(),
        role: dbRow.role || user.role,
        groups: normalizeGroups(user.groups).concat(
          dbRow.role ? [dbRow.role] : []
        ),
      };
    }

    req.user = user;

    dbg("requireSessionAuth resolved req.user", {
      email: req.user.email,
      username: req.user.username,
      role: req.user.role,
      groups: req.user.groups,
      user_type: req.user.user_type,
    });

    return next();
  } catch (err) {
    return next(createError(err.status || 401, err.message));
  }
}

/* ---------------- UNIFIED AUTH ---------------- */
/**
 * ✅ FIX:
 * consider passport session store as authenticated as well
 */
export function requireAuth(req, res, next) {
  if (req.session?.user || req.session?.passport?.user) {
    return requireSessionAuth(req, res, next);
  }

  if ((req.headers.authorization || "").startsWith("Bearer ")) {
    return requireBpAuth(req, res, next);
  }

  return next(createError(401, "Not authenticated"));
}

/* ---------------- Option A Guards ---------------- */

export function requireInternalOnly(req, _res, next) {
  if (req.user?.user_type !== "internal")
    return next(createError(403, "Internal access only"));
  return next();
}

export async function requireAdminOrAccountingDb(req, _res, next) {
  try {
    if (req.user?.user_type !== "internal") {
      dbg("requireAdminOrAccountingDb DENY user_type", {
        user_type: req.user?.user_type,
      });
      return next(createError(403, "Forbidden"));
    }

    const email = (req.user?.email || "").toLowerCase().trim();
    const username = req.user?.username ? String(req.user.username).trim() : "";

    dbg("requireAdminOrAccountingDb lookup", { email, username });

    let rows = [];

    if (email) {
      const r = await query(
        `
        SELECT TOP 1 role, is_active, email, username
        FROM users
        WHERE LOWER(email)=LOWER(@p1) AND user_type='internal'
        ORDER BY updated_at DESC;
        `,
        [email]
      );
      rows = r.rows;
    }

    if (!rows.length && username) {
      const r2 = await query(
        `
        SELECT TOP 1 role, is_active, email, username
        FROM users
        WHERE LOWER(username)=LOWER(@p1) AND user_type='internal'
        ORDER BY updated_at DESC;
        `,
        [username]
      );
      rows = r2.rows;
    }

    dbg("requireAdminOrAccountingDb db result", { rows });

    if (!rows.length) return next(createError(403, "Forbidden"));

    if (rows[0].is_active === 0 || rows[0].is_active === false)
      return next(createError(403, "User disabled"));

    const role = String(rows[0].role || "")
      .toLowerCase()
      .trim();
    const allowed = new Set(["admin", "accounting", "ssp_admins"]);

    if (!allowed.has(role)) {
      dbg("requireAdminOrAccountingDb DENY role", { role });
      return next(createError(403, "Forbidden"));
    }

    // attach canonical email/role
    req.user.role = rows[0].role;
    req.user.email = (rows[0].email || req.user.email || "")
      .toLowerCase()
      .trim();

    dbg("requireAdminOrAccountingDb ALLOW", {
      role: req.user.role,
      email: req.user.email,
    });

    return next();
  } catch (e) {
    console.error("❌ requireAdminOrAccountingDb error:", e);
    return next(createError(500, e.message || "Role check failed"));
  }
}

/* ---------------- Backward compatibility ---------------- */

export const requireInternalAuth = requireInternalOnly;
export const authenticateToken = requireAuth;
