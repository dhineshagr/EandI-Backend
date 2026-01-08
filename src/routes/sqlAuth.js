// src/routes/sqlAuth.js
import { Router } from "express";
import bcrypt from "bcrypt";
import { query } from "../db.js";

const router = Router();
console.log(await bcrypt.hash("Password123", 10));
/* ===============================
   SQL LOGIN (BUSINESS PARTNER)
================================ */
router.post("/sql/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Missing credentials" });
    }

    const { rows } = await query(
      `
      SELECT TOP 1
        User_ID,
        Username,
        Password_Hash,
        Email,
        Display_Name,
        User_Type,
        Role,
        BP_Code
      FROM Users
      WHERE Username = @p1
        AND Is_Active = 1
      `,
      [username]
    );

    if (!rows.length) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.Password_Hash);

    if (!valid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // ✅ Persist SQL session
    req.session.user = {
      authenticated: true,
      user: {
        user_id: user.User_ID,
        username: user.Username,
        email: user.Email,
        display_name: user.Display_Name,
        user_type: user.User_Type?.toLowerCase(),
        role: user.Role,
        bp_code: user.BP_Code,
        roles: [user.Role],
      },
    };

    res.json({ success: true });
  } catch (err) {
    console.error("❌ SQL login failed:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

export default router;
