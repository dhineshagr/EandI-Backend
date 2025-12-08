import { Router } from "express";
import { query } from "../db.js";
import { requireInternalAuth, safeParseUrl } from "../middleware/auth.js";
import bcrypt from "bcryptjs";

const router = Router();

/**
 * Manage users in users
 * With audit logging in users_audit_log
 */

// helper: insert into audit log
async function logUserAction(userId, action, oldValues, newValues, changedBy) {
  await query(
    `INSERT INTO users_audit_log 
       (user_id, action, old_values, new_values, changed_by, created_at_utc)
     VALUES (@p1, @p2, @p3, @p4, @p5, GETDATE());`,
    [
      userId,
      action,
      oldValues ? JSON.stringify(oldValues) : null,
      newValues ? JSON.stringify(newValues) : null,
      changedBy || "system",
    ]
  );
}

// 🔹 List all users
router.get("/", requireInternalAuth, async (req, res) => {
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

// 🔹 Create user
router.post("/", requireInternalAuth, async (req, res) => {
  try {
    safeParseUrl(req);

    const {
      username,
      email,
      role = "User",
      password,
      user_type,
      bp_code,
      okta_id,
      display_name,
    } = req.body || {};

    if (!username || !email) {
      return res.status(400).json({ error: "Username and email are required" });
    }

    // 🔎 Check for duplicate email
    const dupCheck = await query(`SELECT 1 FROM users WHERE email=@p1;`, [
      email,
    ]);
    if (dupCheck.rows.length > 0) {
      return res.status(400).json({ error: "Email already exists" });
    }

    let hash = null;
    if (password) {
      hash = await bcrypt.hash(password, 10);
    }

    const { rows } = await query(
      `INSERT INTO users 
         (username, email, role, user_type, bp_code, okta_id, display_name, password_hash, is_active, created_at, updated_at)
       OUTPUT INSERTED.user_id, INSERTED.username, INSERTED.email, INSERTED.role, 
              INSERTED.user_type, INSERTED.bp_code, INSERTED.okta_id, 
              INSERTED.display_name, INSERTED.is_active
       VALUES (@p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, 1, GETDATE(), GETDATE());`,
      [
        username,
        email,
        role,
        user_type || "bp",
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

// 🔹 Update user
router.put("/:id", requireInternalAuth, async (req, res) => {
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

    // check existing user
    const oldRes = await query(`SELECT * FROM users WHERE user_id=@p1;`, [id]);
    if (!oldRes.rows.length)
      return res.status(404).json({ error: "User not found" });
    const oldUser = oldRes.rows[0];

    let setParts = [];
    let values = [];
    let idx = 1;

    if (username !== undefined) {
      setParts.push(`username=@p${idx++}`);
      values.push(username);
    }
    if (role !== undefined) {
      setParts.push(`role=@p${idx++}`);
      values.push(role);
    }
    if (is_active !== undefined) {
      setParts.push(`is_active=@p${idx++}`);
      values.push(is_active);
    }
    if (display_name !== undefined) {
      setParts.push(`display_name=@p${idx++}`);
      values.push(display_name);
    }
    if (bp_code !== undefined) {
      setParts.push(`bp_code=@p${idx++}`);
      values.push(bp_code);
    }
    if (okta_id !== undefined) {
      setParts.push(`okta_id=@p${idx++}`);
      values.push(okta_id);
    }
    if (email !== undefined) {
      setParts.push(`email=@p${idx++}`);
      values.push(email);
    }
    if (user_type !== undefined) {
      setParts.push(`user_type=@p${idx++}`);
      values.push(user_type);
    }
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      setParts.push(`password_hash=@p${idx++}`);
      values.push(hash);
    }

    if (setParts.length === 0) {
      return res.status(400).json({ error: "No fields to update" });
    }

    values.push(id);

    const { rows } = await query(
      `UPDATE users
       SET ${setParts.join(", ")}, updated_at=GETDATE()
       OUTPUT INSERTED.user_id, INSERTED.username, INSERTED.email, INSERTED.role, 
              INSERTED.user_type, INSERTED.bp_code, INSERTED.okta_id, 
              INSERTED.display_name, INSERTED.is_active
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

// 🔹 Toggle user active/inactive
router.put("/:id/status", requireInternalAuth, async (req, res) => {
  try {
    safeParseUrl(req);

    const { id } = req.params;
    const { is_active } = req.body;

    if (typeof is_active !== "boolean") {
      return res.status(400).json({ error: "is_active must be true or false" });
    }

    const { rows } = await query(
      `UPDATE users
       SET is_active=@p1, updated_at=GETDATE()
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
    res.status(500).json({ error: "Failed to toggle user status" });
  }
});

// 🔹 Delete user
router.delete("/:id", requireInternalAuth, async (req, res) => {
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

    const delRes = await query(
      `DELETE FROM users WHERE user_id=@p1;`,
      [id]
    );

    await logUserAction(id, "delete", { old: oldUser }, null, req.user?.email);
    res.json({ ok: true });
  } catch (err) {
    console.error("❌ DELETE /users/:id error:", err);
    res.status(500).json({ error: "Failed to delete user" });
  }
});

// 🔹 List user audit logs
router.get("/audit/logs", requireInternalAuth, async (req, res) => {
  try {
    safeParseUrl(req);

    const { rows } = await query(
      `SELECT TOP 50
          l.audit_id, l.user_id, u.username, u.email, l.action, l.context, l.created_at_utc,
          l.old_values, l.new_values, l.changed_by
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
