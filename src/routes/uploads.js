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
    "",
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
  requestedName,
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
    let {
      filename,
      report_type = "Sales",
      note = "",
      period = null,
      bp_code = null,
      contract_id = null,
      related_report_number = null,
    } = req.body || {};

    const user = req.user || {};

    if (!filename) {
      return res.status(400).json({ error: "Missing filename" });
    }

    filename = String(filename).trim();
    report_type = String(report_type || "Sales").trim();
    period = period ? String(period).trim() : null;
    bp_code = bp_code ? String(bp_code).trim() : null;
    contract_id = contract_id ? String(contract_id).trim() : null;
    note = note ? String(note).trim() : "";

    related_report_number =
      related_report_number !== null &&
      related_report_number !== undefined &&
      String(related_report_number).trim() !== ""
        ? Number(related_report_number)
        : null;

    const finalBpCode =
      user.user_type === "bp" ? user.bp_code || bp_code || null : bp_code;

    if (!period) {
      return res.status(400).json({
        error: "Period is required",
      });
    }

    const uploadedBy =
      user.user_type === "bp"
        ? String(user.email || "")
        : String(user.user_id || user.username || user.email || "");

    if (!uploadedBy) {
      return res.status(401).json({
        error: "Missing user identity",
      });
    }

    const uploadedByName =
      user.display_name ||
      user.fullName ||
      user.name ||
      user.username ||
      user.email ||
      "System";

    const uploadedByType = user.user_type || "internal";

    console.log("📥 Register Upload Payload:", {
      filename,
      report_type,
      period,
      bp_code: finalBpCode,
      contract_id,
      related_report_number,
      user_type: user.user_type,
      uploadedBy,
    });

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
        Uploaded_By_Type,
        Period,
        BP_Code,
        Contract_ID,
        Related_Report_Number
      )
      OUTPUT
        INSERTED.Report_Number AS report_number,
        INSERTED.Report_Type AS report_type,
        INSERTED.Filename AS filename,
        INSERTED.Uploaded_By AS uploaded_by,
        INSERTED.Uploaded_By_Name AS uploaded_by_name,
        INSERTED.Uploaded_At_UTC AS uploaded_at_utc,
        INSERTED.Status AS status,
        INSERTED.Uploaded_By_Type AS uploaded_by_type,
        INSERTED.Period AS period,
        INSERTED.BP_Code AS bp_code,
        INSERTED.Contract_ID AS contract_id,
        INSERTED.Related_Report_Number AS related_report_number
      VALUES
      (
        @p1, @p2, @p3, GETUTCDATE(),
        'new', @p4, @p5, @p6, @p7, @p8, @p9, @p10
      );
    `;

    const params = [
      report_type,
      filename,
      uploadedBy,
      note,
      uploadedByName,
      uploadedByType,
      period,
      finalBpCode,
      contract_id,
      related_report_number,
    ];

    const { rows } = await query(sql, params);
    const inserted = rows?.[0];

    console.log("✅ Upload registered:", inserted);

    return res.json({
      success: true,
      data: inserted,
      report_number: inserted?.report_number,
      status: inserted?.status || "new",
      message:
        "Upload registered successfully. Processing will continue through the backend workflow.",
    });
  } catch (err) {
    console.error("❌ /uploads/register error:", err);

    return res.status(500).json({
      error: "Failed to register upload",
      details: err.message,
    });
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
        [reportNumber],
      );

      if (!rows?.length) {
        return res.status(404).json({ error: "Report not found" });
      }

      requestedFilename = rows[0].Filename;
      console.log(
        "📥 [DOWNLOAD] report_number -> filename:",
        requestedFilename,
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
      requestedFilename,
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

/* ============================================================================
   GET /api/uploads/lookups/suppliers?q=
============================================================================ */
router.get("/lookups/suppliers", requireAuth, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();

    if (q.length < 1) {
      return res.json({ items: [] });
    }

    const { rows } = await query(
      `
      SELECT TOP 20
        BP_Code AS bp_code
      FROM dbo.Ref_Contract
      WHERE BP_Code LIKE @p1
      GROUP BY BP_Code
      ORDER BY BP_Code;
      `,
      [`%${q}%`],
    );

    res.json({ items: rows || [] });
  } catch (err) {
    console.error("❌ supplier lookup error:", err);
    res.status(500).json({ error: "Failed to search suppliers" });
  }
});

/* ============================================================================
   GET /api/uploads/lookups/contracts?q=
============================================================================ */
router.get("/lookups/contracts", requireAuth, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();

    if (q.length < 1) {
      return res.json({ items: [] });
    }

    const { rows } = await query(
      `
      SELECT TOP 20
        Contract_ID AS contract_id,
        CAST(Contract_ID AS NVARCHAR(255)) AS contract_name
      FROM dbo.Ref_Contract
      WHERE CAST(Contract_ID AS NVARCHAR(255)) LIKE @p1
      GROUP BY Contract_ID
      ORDER BY Contract_ID;
      `,
      [`%${q}%`],
    );

    res.json({ items: rows || [] });
  } catch (err) {
    console.error("❌ contract lookup error:", err);
    res.status(500).json({ error: "Failed to search contracts" });
  }
});

export default router;
