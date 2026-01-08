import { Router } from "express";
import { query } from "../db.js";

const router = Router();

router.get("/health", async (_req, res) => {
  try {
    await query("SELECT 1");

    res.json({
      ok: true,
      service: "ssp-api",
      database: "connected",
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error("❌ Health check failed:", err.message);

    res.status(500).json({
      ok: false,
      service: "ssp-api",
      database: "disconnected",
      timestamp: new Date().toISOString(),
    });
  }
});

export default router;
