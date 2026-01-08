// src/routes/me.js
import { Router } from "express";
import { query } from "../db.js";

const router = Router();

// Turn on only while debugging
const DEBUG_ME = true;
function dbg(label, obj) {
  if (!DEBUG_ME) return;
  console.log(`🧩 [ME DEBUG] ${label}`, obj);
}

// ✅ Support BOTH session shapes:
// A) NEW/FLAT:   req.session.user = { email, user_type, groups... } AND req.session.authenticated=true
// B) OLD/NESTED: req.session.user = { authenticated:true, user:{...} }
function getSessionUser(req) {
  const u = req.session?.user;

  // OLD/NESTED
  if (u && typeof u === "object" && u.user && u.authenticated === true) {
    return u.user;
  }

  // NEW/FLAT (your updated auth.js)
  if (u && typeof u === "object" && (u.email || u.nameID || u.username)) {
    return u;
  }

  // passport sometimes stores at req.session.passport.user
  const p = req.session?.passport?.user;
  if (p && typeof p === "object") return p;

  return null;
}

router.get("/me", async (req, res) => {
  try {
    dbg("SESSION SNAPSHOT", {
      hasSession: Boolean(req.session),
      hasUser: Boolean(req.session?.user),
      topKeys: req.session ? Object.keys(req.session) : [],
      userKeys: req.session?.user ? Object.keys(req.session.user) : [],
      hasPassport: Boolean(req.session?.passport),
      passportKeys: req.session?.passport
        ? Object.keys(req.session.passport)
        : [],
    });

    // ✅ Auth check supports BOTH styles
    const isAuthed =
      req.session?.authenticated === true ||
      req.session?.user?.authenticated === true ||
      Boolean(req.session?.passport?.user);

    if (!isAuthed) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    const sessionUser = getSessionUser(req);

    dbg("SESSION USER (resolved)", sessionUser);

    if (!sessionUser) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    // Determine user type
    const userTypeRaw = String(sessionUser.user_type || "").toLowerCase();
    const isInternal = userTypeRaw === "internal" || userTypeRaw === "okta";
    const isBp = userTypeRaw === "bp";

    let rows;

    // =========================
    // INTERNAL USER (OKTA)
    // =========================
    if (isInternal || (!userTypeRaw && sessionUser.email)) {
      const email = String(sessionUser.email || "")
        .toLowerCase()
        .trim();
      if (!email) {
        return res.status(401).json({ error: "Missing email in session" });
      }

      ({ rows } = await query(
        `
        SELECT TOP 1
          user_id,
          user_type,
          username,
          email,
          display_name,
          role,
          bp_code,
          is_active
        FROM users
        WHERE LOWER(email) = LOWER(@p1)
          AND is_active = 1
        ORDER BY updated_at DESC;
        `,
        [email]
      ));
    }

    // =========================
    // BUSINESS PARTNER (SQL LOGIN)
    // =========================
    else if (isBp) {
      const username = String(sessionUser.username || "").trim();
      if (!username) {
        return res.status(401).json({ error: "Missing username in session" });
      }

      ({ rows } = await query(
        `
        SELECT TOP 1
          user_id,
          user_type,
          username,
          email,
          display_name,
          role,
          bp_code,
          is_active
        FROM users
        WHERE LOWER(username) = LOWER(@p1)
          AND is_active = 1
        ORDER BY updated_at DESC;
        `,
        [username]
      ));
    } else {
      return res.status(403).json({ error: "Unknown user type" });
    }

    // Must exist in DB
    if (!rows || rows.length === 0) {
      return res.status(403).json({ error: "User not registered in system" });
    }

    const dbUser = rows[0];

    // ✅ Normalize to ONE standard shape for frontend + middleware
    const normalized = {
      authenticated: true,
      user: {
        user_id: dbUser.user_id,
        user_type: dbUser.user_type, // internal | bp
        username: dbUser.username,
        email: dbUser.email,
        display_name: dbUser.display_name,
        role: dbUser.role,
        bp_code: dbUser.bp_code,
        roles: dbUser.role ? [dbUser.role] : [],
        groups: dbUser.role ? [dbUser.role] : [],
      },
    };

    // Store normalized session in the OLD/NESTED shape (for compatibility)
    req.session.user = normalized;
    req.session.authenticated = true;

    // Ensure cookie is persisted
    req.session.save(() => {
      return res.json(normalized);
    });
  } catch (err) {
    console.error("❌ /api/me error:", err);
    return res.status(500).json({ error: "Failed to load user profile" });
  }
});

export default router;
