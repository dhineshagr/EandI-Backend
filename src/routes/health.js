import { Router } from "express";
import { query } from "../db.js";
const router = Router();

router.get("/health", async (_req, res) => {
  try {
    await query("SELECT 1");
    res.json({ ok: true });
  } catch {
    res.status(500).json({ ok: false });
  }
});

export default router;
