import { Router } from "express";
import { query } from "../db.js";
import {
  requireAuth,
  requireInternalOnly,
  requireAdminOrAccountingDb,
  safeParseUrl,
} from "../middleware/auth.js";
import bcrypt from "bcryptjs";

const router = Router();
const ADMIN_MW = [requireAuth, requireInternalOnly, requireAdminOrAccountingDb];

/* ============================================================================
   Audit helper
============================================================================ */
async function logUserAction(userId, action, oldValues, newValues, changedBy) {
  try {
    await query(
      `INSERT INTO users_audit_log
        (user_id, action, old_values, new_values, changed_by, created_at_utc)
       VALUES (@p1, @p2, @p3, @p4, @p5, GETUTCDATE());`,
      [
        userId,
        action,
        oldValues ? JSON.stringify(oldValues) : null,
        newValues ? JSON.stringify(newValues) : null,
        changedBy || "system",
      ]
    );
  } catch (err) {
    console.warn("⚠️ users_audit_log skipped:", err.message);
  }
}

/* ============================================================================
   GET /users — List users (Admin/Accounting only)
============================================================================ */
router.get("/", ...ADMIN_MW, async (req, res) => {
  try {
    safeParseUrl(req);

    const { rows } = await query(
      `SELECT
          user_id,
          user_type,
          username,
          display_name,
          email,
          bp_code,
          okta_id,
          role,
          is_active,
          created_at,
          updated_at
        FROM users
        ORDER BY user_id ASC;`
    );

    res.json({ users: rows });
  } catch (err) {
    console.error("❌ GET /users error:", err);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

/* ============================================================================
   POST /users — Create user (Admin/Accounting only)
============================================================================ */
router.post("/", ...ADMIN_MW, async (req, res) => {
  try {
    safeParseUrl(req);

    const {
      username,
      email,
      role = "User",
      password,
      user_type = "bp",
      bp_code,
      okta_id,
      display_name,
    } = req.body || {};

    if (!username || !email) {
      return res.status(400).json({ error: "Username and email are required" });
    }

    const dupCheck = await query(
      `SELECT 1 FROM users WHERE LOWER(email)=LOWER(@p1);`,
      [email]
    );
    if (dupCheck.rows.length) {
      return res.status(400).json({ error: "Email already exists" });
    }

    const hash = password ? await bcrypt.hash(password, 10) : null;

    const { rows } = await query(
      `INSERT INTO users
        (username, email, role, user_type, bp_code, okta_id, display_name,
         password_hash, is_active, created_at, updated_at)
       OUTPUT
         INSERTED.user_id,
         INSERTED.username,
         INSERTED.email,
         INSERTED.role,
         INSERTED.user_type,
         INSERTED.bp_code,
         INSERTED.okta_id,
         INSERTED.display_name,
         INSERTED.is_active
       VALUES
         (@p1,@p2,@p3,@p4,@p5,@p6,@p7,@p8,1,GETUTCDATE(),GETUTCDATE());`,
      [
        username,
        email,
        role,
        user_type,
        bp_code || null,
        okta_id || null,
        display_name || null,
        hash,
      ]
    );

    const user = rows[0];

    await logUserAction(
      user.user_id,
      "create",
      null,
      { new: user },
      req.user?.email
    );

    res.json({ user });
  } catch (err) {
    console.error("❌ POST /users error:", err);
    res.status(500).json({ error: "Failed to create user" });
  }
});

/* ============================================================================
   PUT /users/:id — Update user (Admin/Accounting only)
============================================================================ */
router.put("/:id", ...ADMIN_MW, async (req, res) => {
  try {
    safeParseUrl(req);

    const { id } = req.params;
    const {
      username,
      role,
      password,
      is_active,
      display_name,
      bp_code,
      okta_id,
      email,
      user_type,
    } = req.body || {};

    const oldRes = await query(`SELECT * FROM users WHERE user_id=@p1;`, [id]);
    if (!oldRes.rows.length)
      return res.status(404).json({ error: "User not found" });
    const oldUser = oldRes.rows[0];

    if (email && email !== oldUser.email) {
      const dup = await query(
        `SELECT 1 FROM users WHERE LOWER(email)=LOWER(@p1) AND user_id<>@p2;`,
        [email, id]
      );
      if (dup.rows.length)
        return res.status(400).json({ error: "Email already in use" });
    }

    const setParts = [];
    const values = [];
    let idx = 1;

    const add = (col, val) => {
      setParts.push(`${col}=@p${idx++}`);
      values.push(val);
    };

    if (username !== undefined) add("username", username);
    if (email !== undefined) add("email", email);
    if (role !== undefined) add("role", role);
    if (user_type !== undefined) add("user_type", user_type);
    if (bp_code !== undefined) add("bp_code", bp_code);
    if (okta_id !== undefined) add("okta_id", okta_id);
    if (display_name !== undefined) add("display_name", display_name);
    if (is_active !== undefined) add("is_active", is_active);

    if (password) add("password_hash", await bcrypt.hash(password, 10));

    if (!setParts.length)
      return res.status(400).json({ error: "No fields to update" });

    values.push(id);

    const { rows } = await query(
      `UPDATE users
       SET ${setParts.join(", ")}, updated_at=GETUTCDATE()
       OUTPUT
         INSERTED.user_id,
         INSERTED.username,
         INSERTED.email,
         INSERTED.role,
         INSERTED.user_type,
         INSERTED.bp_code,
         INSERTED.okta_id,
         INSERTED.display_name,
         INSERTED.is_active
       WHERE user_id=@p${idx};`,
      values
    );

    const updatedUser = rows[0];

    await logUserAction(
      id,
      "update",
      { old: oldUser },
      { new: updatedUser },
      req.user?.email
    );

    res.json({ user: updatedUser });
  } catch (err) {
    console.error("❌ PUT /users/:id error:", err);
    res.status(500).json({ error: "Failed to update user" });
  }
});

/* ============================================================================
   PUT /users/:id/status — Enable/Disable (Admin/Accounting only)
============================================================================ */
router.put("/:id/status", ...ADMIN_MW, async (req, res) => {
  try {
    safeParseUrl(req);

    const { id } = req.params;
    const { is_active } = req.body;

    if (typeof is_active !== "boolean") {
      return res.status(400).json({ error: "is_active must be boolean" });
    }

    const { rows } = await query(
      `UPDATE users
       SET is_active=@p1, updated_at=GETUTCDATE()
       OUTPUT INSERTED.user_id, INSERTED.username, INSERTED.email, INSERTED.role, INSERTED.is_active
       WHERE user_id=@p2;`,
      [is_active, id]
    );

    const updatedUser = rows[0];

    await logUserAction(
      id,
      is_active ? "enable" : "disable",
      null,
      { new: updatedUser },
      req.user?.email
    );

    res.json({ user: updatedUser });
  } catch (err) {
    console.error("❌ PUT /users/:id/status error:", err);
    res.status(500).json({ error: "Failed to update status" });
  }
});

/* ============================================================================
   DELETE /users/:id — Delete (Admin/Accounting only)
============================================================================ */
router.delete("/:id", ...ADMIN_MW, async (req, res) => {
  try {
    safeParseUrl(req);

    const { id } = req.params;

    const oldRes = await query(
      `SELECT user_id, username, email, role FROM users WHERE user_id=@p1;`,
      [id]
    );
    if (!oldRes.rows.length)
      return res.status(404).json({ error: "User not found" });

    const oldUser = oldRes.rows[0];

    await query(`DELETE FROM users WHERE user_id=@p1;`, [id]);

    await logUserAction(id, "delete", { old: oldUser }, null, req.user?.email);

    res.json({ ok: true });
  } catch (err) {
    console.error("❌ DELETE /users/:id error:", err);
    res.status(500).json({ error: "Failed to delete user" });
  }
});

/* ============================================================================
   GET /users/audit/logs — Audit logs (Admin/Accounting only)
============================================================================ */
router.get("/audit/logs", ...ADMIN_MW, async (req, res) => {
  try {
    safeParseUrl(req);

    const { rows } = await query(
      `SELECT TOP 50
         l.audit_id,
         l.user_id,
         u.username,
         u.email,
         l.action,
         l.old_values,
         l.new_values,
         l.changed_by,
         l.created_at_utc
       FROM users_audit_log l
       LEFT JOIN users u ON l.user_id = u.user_id
       ORDER BY l.created_at_utc DESC;`
    );

    res.json({ logs: rows });
  } catch (err) {
    console.error("❌ GET /users/audit/logs error:", err);
    res.status(500).json({ error: "Failed to fetch audit logs" });
  }
});

export default router;
