// src/routes/uploads.js
import express from "express";
import path from "path";
import { requireAuth, safeParseUrl } from "../middleware/auth.js";
import { query } from "../db.js";
import { BlobServiceClient } from "@azure/storage-blob";

const router = express.Router();

/* ============================================================================
   Helpers
============================================================================ */

// Normalize any filename/blob name for comparison
function normalizeName(input) {
  if (!input) return "";

  let s = String(input);

  // take only last segment if it's a blob path
  s = s.split("/").pop();

  // decode any %xx encoding safely
  try {
    s = decodeURIComponent(s);
  } catch {}

  s = s.trim().toLowerCase();

  // remove common timestamp prefixes like: 20260105_ or 2026-01-05t123000_
  // also handles 2026-01-05T1937_ (your real example)
  s = s.replace(/^(\d{4}[-]?\d{2}[-]?\d{2}(t?\d{3,})?[_-]+)/i, "");

  // normalize separators: spaces, underscores, dashes -> single space
  s = s.replace(/[\s_-]+/g, " ");

  // remove punctuation except dot (keep extension)
  s = s.replace(/[^\w.\s]/g, "");

  // collapse multiple spaces
  s = s.replace(/\s+/g, " ").trim();

  return s;
}

function getContentTypeByExt(filename) {
  const ext = (path.extname(filename || "").toLowerCase() || "").replace(
    ".",
    ""
  );
  const map = {
    csv: "text/csv",
    txt: "text/plain",
    xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    xls: "application/vnd.ms-excel",
    pdf: "application/pdf",
    json: "application/json",
  };
  return map[ext] || "application/octet-stream";
}

async function findBlobByLooseName(
  blobServiceClient,
  containers,
  requestedName
) {
  const reqNorm = normalizeName(requestedName);

  for (const containerName of containers) {
    const containerClient = blobServiceClient.getContainerClient(containerName);
    if (!(await containerClient.exists())) continue;

    // NOTE: This scans blobs; long term you should store container+blobName in DB
    for await (const blob of containerClient.listBlobsFlat()) {
      const blobNorm = normalizeName(blob.name);

      // Exact normalized match is best
      if (blobNorm === reqNorm) {
        return { containerClient, blobName: blob.name };
      }

      // Loose contains match as fallback (helps when DB has display name)
      if (blobNorm.includes(reqNorm) || reqNorm.includes(blobNorm)) {
        return { containerClient, blobName: blob.name };
      }
    }
  }

  return null;
}

/* ============================================================================
   POST /api/uploads/register
============================================================================ */
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
        : String(user.user_id || user.username || user.email);

    const uploadedByName =
      user.display_name ||
      user.fullName ||
      user.name ||
      user.username ||
      user.email ||
      "System";

    const uploadedByType = user.user_type || "internal";

    const sql = `
      INSERT INTO dbo.Report_Number
      (
        Report_Type,
        Filename,
        Uploaded_By,
        Uploaded_At_UTC,
        Status,
        Note,
        Uploaded_By_Name,
        Uploaded_By_Type
      )
      OUTPUT
        INSERTED.Report_Number,
        INSERTED.Report_Type,
        INSERTED.Filename,
        INSERTED.Uploaded_By,
        INSERTED.Uploaded_By_Name,
        INSERTED.Uploaded_At_UTC,
        INSERTED.Status,
        INSERTED.Uploaded_By_Type
      VALUES
      (
        @p1, @p2, @p3, GETUTCDATE(),
        'new', @p4, @p5, @p6
      );
    `;

    const params = [
      report_type,
      filename,
      uploadedBy,
      note,
      uploadedByName,
      uploadedByType,
    ];

    const { rows } = await query(sql, params);
    res.json({ success: true, data: rows?.[0] });
  } catch (err) {
    console.error("❌ /uploads/register error:", err);
    res.status(500).json({ error: "Failed to register upload" });
  }
});

/* ============================================================================
   GET /api/uploads/recent
============================================================================ */
/* ============================================================================
   GET /api/uploads/recent
   Rules:
   - BP: only their uploads
   - Internal Admin/Accounting/SSP_Admins: all uploads
   - Other internal users: only their uploads
============================================================================ */
router.get("/recent", requireAuth, async (req, res) => {
  try {
    const url = safeParseUrl(req);
    const reportType = url.searchParams.get("report_type");
    const user = req.user;

    const role = String(user.role || "")
      .toLowerCase()
      .trim();

    // ✅ privileged internal users see ALL uploads
    const isPrivilegedInternal =
      user.user_type === "internal" &&
      ["admin", "accounting", "ssp_admins"].includes(role);

    let sql = `
      SELECT TOP 20
        Report_Number        AS report_number,
        Report_Type          AS report_type,
        Filename             AS filename,
        Uploaded_By          AS uploaded_by,
        ISNULL(Uploaded_By_Name, Uploaded_By) AS uploaded_by_name,
        Uploaded_At_UTC      AS uploaded_at_utc,
        Status               AS status,
        Uploaded_By_Type     AS uploaded_by_type
      FROM dbo.Report_Number
    `;

    const params = [];

    // ✅ Non-privileged users see ONLY their uploads
    if (!isPrivilegedInternal) {
      const uploadedByValue =
        user.user_type === "bp"
          ? String(user.email || "").trim()
          : String(user.user_id || user.username || user.email || "").trim();

      if (!uploadedByValue) {
        return res.status(401).json({ error: "Missing user identity" });
      }

      sql += `
        WHERE LOWER(Uploaded_By) = LOWER(@p1)
      `;
      params.push(uploadedByValue);
    }

    // Optional report_type filter
    if (reportType) {
      sql += params.length ? " AND" : " WHERE";
      sql += ` Report_Type = @p${params.length + 1}`;
      params.push(reportType);
    }

    sql += " ORDER BY Uploaded_At_UTC DESC;";

    const { rows } = await query(sql, params);

    // ✅ include download_key so frontend can use report_number for download
    const items = (rows || []).map((r) => ({
      ...r,
      download_key: r.report_number,
    }));

    res.json({ items });
  } catch (err) {
    console.error("❌ /uploads/recent error:", err);
    res.status(500).json({ error: "Failed to fetch uploads" });
  }
});

/* ============================================================================
   GET /api/uploads/download/:fileKey
   - fileKey can be report_number (numeric) OR filename (string)
============================================================================ */
router.get("/download/:fileKey", requireAuth, async (req, res) => {
  try {
    const rawKey = req.params.fileKey;
    if (!rawKey) return res.status(400).json({ error: "Missing file key" });

    const keyDecoded = (() => {
      try {
        return decodeURIComponent(rawKey).trim();
      } catch {
        return String(rawKey).trim();
      }
    })();

    console.log("📥 [DOWNLOAD] request key:", keyDecoded);

    // 1) If numeric -> treat as report_number and fetch filename from DB
    let requestedFilename = keyDecoded;

    if (/^\d+$/.test(keyDecoded)) {
      const reportNumber = Number(keyDecoded);

      const { rows } = await query(
        `
        SELECT TOP 1 Filename
        FROM dbo.Report_Number
        WHERE Report_Number = @p1
        ORDER BY Uploaded_At_UTC DESC;
        `,
        [reportNumber]
      );

      if (!rows?.length) {
        return res.status(404).json({ error: "Report not found" });
      }

      requestedFilename = rows[0].Filename;
      console.log(
        "📥 [DOWNLOAD] report_number -> filename:",
        requestedFilename
      );
    }

    // 2) Find in Azure Blob (loose match)
    const conn = process.env.AZURE_STORAGE_CONNECTION_STRING;
    if (!conn) {
      return res
        .status(500)
        .json({ error: "Azure storage connection missing" });
    }

    const blobServiceClient = BlobServiceClient.fromConnectionString(conn);

    // ✅ FIX: include dataintegration (your blob is here)
    // Use env to control in each environment
    const containers = (
      process.env.AZURE_DOWNLOAD_CONTAINERS ||
      "dataintegration,ssp-reports,members,suppliers,internal"
    )
      .split(",")
      .map((c) => c.trim())
      .filter(Boolean);

    const found = await findBlobByLooseName(
      blobServiceClient,
      containers,
      requestedFilename
    );

    if (!found) {
      console.warn("📥 [DOWNLOAD] NOT FOUND for:", requestedFilename, {
        normalized: normalizeName(requestedFilename),
        containers,
      });
      return res.status(404).json({ error: "File not found" });
    }

    const { containerClient, blobName } = found;
    console.log("📥 [DOWNLOAD] matched blob:", {
      container: containerClient.containerName,
      blobName,
      blobNorm: normalizeName(blobName),
      reqNorm: normalizeName(requestedFilename),
    });

    const blobClient = containerClient.getBlobClient(blobName);
    const download = await blobClient.download();

    const finalName = requestedFilename || blobName.split("/").pop();

    res.setHeader("Content-Disposition", `attachment; filename="${finalName}"`);
    res.setHeader("Content-Type", getContentTypeByExt(finalName));

    download.readableStreamBody.pipe(res);
  } catch (err) {
    console.error("❌ /uploads/download error:", err);
    res.status(500).json({ error: "Failed to download file" });
  }
});

export default router;
