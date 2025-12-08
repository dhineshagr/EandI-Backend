import express from "express";
import { requireAuth, safeParseUrl } from "../middleware/auth.js";
import { pool } from "../db.js";
import { BlobServiceClient } from "@azure/storage-blob";

const router = express.Router();

/**
 * ==========================================================
 * POST /api/uploads/register
 * Save upload metadata after file upload (main: report_number)
 * ==========================================================
 */
router.post("/register", requireAuth, async (req, res) => {
  try {
    const { filename, report_type = "Sales", note = "" } = req.body;
    const user = req.user;

    if (!filename) {
      return res.status(400).json({ error: "Missing filename" });
    }

    const uploadedBy =
      user.user_type === "bp"
        ? user.email
        : user.user_id?.toString() || user.username || user.email;

    const uploadedByName =
      user.fullName || user.name || user.username || user.email;

    const uploadedByType = user.user_type || "internal";

    // ✅ MSSQL INSERT with OUTPUT
    const sql = `
      INSERT INTO report_number
        (report_type, filename, uploaded_by, uploaded_at_utc, status, note, uploaded_by_name, uploaded_by_type)
      OUTPUT INSERTED.report_number, INSERTED.report_type, INSERTED.filename,
             INSERTED.uploaded_by, INSERTED.uploaded_at_utc, INSERTED.status,
             INSERTED.uploaded_by_name, INSERTED.uploaded_by_type
      VALUES
        (@p1, @p2, @p3, GETDATE(), 'new', @p4, @p5, @p6);
    `;

    const params = [
      report_type, // @p1
      filename, // @p2
      uploadedBy, // @p3
      note, // @p4
      uploadedByName, // @p5
      uploadedByType, // @p6
    ];

    const result = await pool.query(sql, params);

    // ✅ Safe fallback for different MSSQL pool return formats
    const inserted =
      result?.recordset?.[0] ||
      result?.recordsets?.[0]?.[0] ||
      result?.rows?.[0] ||
      null;

    if (!inserted) {
      console.warn("⚠️ Insert executed but no recordset returned:", result);
      return res.status(200).json({
        success: true,
        message: "Upload registered (no result returned)",
      });
    }

    console.log("✅ Upload registered:", inserted);
    res.status(200).json({ success: true, data: inserted });
  } catch (err) {
    console.error("❌ /uploads/register error:", err.stack || err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * ==========================================================
 * GET /api/uploads/recent
 * Fetch last 20 uploads (admins see all)
 * ==========================================================
 */
router.get("/recent", requireAuth, async (req, res) => {
  try {
    // Parse query parameters safely
    let url;
    try {
      url = safeParseUrl(req) || { searchParams: new URLSearchParams() };
    } catch {
      url = { searchParams: new URLSearchParams() };
    }

    const reportType = url.searchParams.get("report_type") || null;
    const user = req.user;

    // Normalize roles
    const roles = Array.isArray(user.roles)
      ? user.roles.map((r) => r.toLowerCase())
      : [(user.role || "").toLowerCase()];
    const isAdmin = roles.includes("admin");

    const uploadedBy =
      user.user_type === "bp"
        ? user.email
        : user.user_id?.toString() || user.username || user.email;

    console.log("🔎 Fetching uploads for:", uploadedBy, "| Roles:", roles);
    const dbCheck = await pool.query("SELECT DB_NAME() AS CurrentDB");
    console.log("🧭 Connected to database:", dbCheck.rows?.[0]?.CurrentDB);

    // ✅ Correct table & column names
    let sql = `
      SELECT TOP 20
        Report_Number AS report_number,
        Report_Type AS report_type,
        FileName AS name,
        Uploaded_By AS uploaded_by_name,
        Uploaded_By_Name AS display_name,
        Uploaded_At_UTC AS date,
        Status AS status,
        Uploaded_By_Type AS uploaded_by_type
      FROM dbo.Report_Number
    `;

    const params = [];

    if (!isAdmin) {
      sql += " WHERE LOWER(Uploaded_By) = LOWER(@p1)";
      params.push(uploadedBy);
    }

    if (reportType) {
      sql += params.length ? " AND" : " WHERE";
      sql += " Report_Type = @p2";
      params.push(reportType);
    }

    sql += " ORDER BY Uploaded_At_UTC DESC;";

    console.log("📘 Executing SQL:", sql, "| Params:", params);

    const result = await pool.query(sql, params);
    const rows = result?.recordset || [];

    console.log(`✅ Found ${rows.length} uploads | Admin: ${isAdmin}`);
    res.json({ items: rows });
  } catch (err) {
    console.error("❌ /uploads/recent error:", err.stack || err.message);
    res.status(500).json({ error: err.message });
  }
});

/**
 * ==========================================================
 * GET /api/uploads/download/:filename
 * Azure Blob secure file download
 * ==========================================================
 */
router.get("/download/:filename", requireAuth, async (req, res) => {
  try {
    let { filename } = req.params;
    if (!filename) return res.status(400).json({ error: "Missing filename" });

    const connStr = process.env.AZURE_STORAGE_CONNECTION_STRING;
    const blobServiceClient = BlobServiceClient.fromConnectionString(connStr);

    // ✅ Try all likely containers
    const containers = ["ssp-reports", "members", "suppliers", "internal"];
    let containerClient = null;

    for (const name of containers) {
      const c = blobServiceClient.getContainerClient(name);
      if (await c.exists()) {
        containerClient = c;
        console.log(`✅ Using Azure container: ${name}`);
        break;
      }
    }

    if (!containerClient) {
      return res.status(500).json({ error: "No valid Azure container found" });
    }

    filename = decodeURIComponent(filename).trim().toLowerCase();
    const normalizedSearch = filename.replace(/\s+/g, "_");

    console.log(`🔍 Searching Azure for: ${normalizedSearch}`);

    const matches = [];
    for await (const blob of containerClient.listBlobsFlat()) {
      const blobName = blob.name.toLowerCase();
      const shortName = blobName.split("/").pop();
      const cleaned = shortName.replace(
        /^(\d{4}[-]?\d{2}[-]?\d{2}t?\d{6,}_)/i,
        ""
      );
      const normalizedBlob = cleaned.replace(/\s+/g, "_").toLowerCase();

      if (normalizedBlob.includes(normalizedSearch)) {
        matches.push({
          fullPath: blob.name,
          lastModified: blob.properties.lastModified,
        });
      }
    }

    if (matches.length === 0) {
      return res
        .status(404)
        .json({ error: `File "${filename}" not found in Azure.` });
    }

    matches.sort((a, b) => new Date(b.lastModified) - new Date(a.lastModified));
    const blobClient = containerClient.getBlobClient(matches[0].fullPath);
    const downloadResponse = await blobClient.download();

    const ext = filename.split(".").pop().toLowerCase();
    const mimeMap = {
      xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      xls: "application/vnd.ms-excel",
      csv: "text/csv",
      pdf: "application/pdf",
      docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      doc: "application/msword",
      zip: "application/zip",
      txt: "text/plain",
    };

    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.setHeader("Content-Type", mimeMap[ext] || "application/octet-stream");
    downloadResponse.readableStreamBody.pipe(res);
  } catch (err) {
    console.error("❌ /uploads/download error:", err.stack || err.message);
    res.status(500).json({ error: "Failed to download file" });
  }
});

export default router;
