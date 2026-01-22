// routes/sspreports.js
import express from "express";
import { query } from "../db.js";
import { requireInternalAuth } from "../middleware/auth.js";

const router = express.Router();

/* ======================================================================
   GET /api/ssp/reports
   SSP Dashboard API
====================================================================== */
// ✅ UPDATED: /ssp/reports route
// - Fixes Status column: computes report_status when header status is NULL/blank
// - Keeps all existing filters/sort/pagination
// - Keeps Uploaded By fields (uploaded_by, uploaded_by_name, uploaded_by_display)

router.get("/ssp/reports", requireInternalAuth, async (req, res) => {
  try {
    const {
      search = "",
      dateType = "Uploaded_At_Utc",
      startDate,
      endDate,
      supplier = "",
      contract = "",
      member = "",
      sort = "uploaded_at_utc",
      order = "desc",
      page = 1,
      limit = 25,
    } = req.query;

    const pageNum = Number(page) || 1;
    const pageSize = Number(limit) || 25;
    const offset = (pageNum - 1) * pageSize;

    /* --------------------------------------------------
       Sorting whitelist
    -------------------------------------------------- */
    const validSortFields = [
      "report_number",
      "report_type",
      "file_name",
      "uploaded_by",
      "uploaded_by_name",
      "uploaded_by_display",
      "uploaded_at_utc",
      "passed_count",
      "failed_count",
      "approved_count",
      "total_purchase",
      "total_caf",
      "report_status",
      "total_rows", // ✅ optional: allows sorting by total rows
    ];

    const sortField = validSortFields.includes(sort) ? sort : "uploaded_at_utc";
    const sortOrder = order === "asc" ? "ASC" : "DESC";

    /* --------------------------------------------------
       Dynamic filters
    -------------------------------------------------- */
    const conditions = [];
    const values = [];
    let idx = 1;

    if (search) {
      conditions.push(`
        (
          CAST(h.Report_Number AS NVARCHAR(50)) LIKE @p${idx}
          OR rn.Filename LIKE @p${idx}
          OR rn.Uploaded_By LIKE @p${idx}
          OR rn.Uploaded_By_Name LIKE @p${idx}
        )
      `);
      values.push(`%${search}%`);
      idx++;
    }

    if (supplier) {
      conditions.push(`h.BP_Code = @p${idx}`);
      values.push(supplier);
      idx++;
    }

    if (contract) {
      conditions.push(`h.Contract_ID = @p${idx}`);
      values.push(contract);
      idx++;
    }

    if (member) {
      conditions.push(`d.Member_Number LIKE @p${idx}`);
      values.push(`%${member}%`);
      idx++;
    }

    if (startDate || endDate) {
      const dateColumn =
        dateType === "Approved_At_Utc"
          ? "h.Approved_At_Utc"
          : "rn.Uploaded_At_Utc";

      if (startDate && endDate) {
        conditions.push(`${dateColumn} BETWEEN @p${idx} AND @p${idx + 1}`);
        values.push(startDate, endDate);
        idx += 2;
      } else if (startDate) {
        conditions.push(`${dateColumn} >= @p${idx}`);
        values.push(startDate);
        idx++;
      } else if (endDate) {
        conditions.push(`${dateColumn} <= @p${idx}`);
        values.push(endDate);
        idx++;
      }
    }

    const whereClause =
      conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    /* --------------------------------------------------
       Main query
       ✅ Key change: compute report_status if header status is NULL/blank
    -------------------------------------------------- */
    const sql = `
      WITH base AS (
        SELECT
          h.Report_Number AS report_number,
          rn.Report_Type AS report_type,
          rn.Filename AS file_name,

          rn.Uploaded_By AS uploaded_by,
          rn.Uploaded_By_Name AS uploaded_by_name,
          COALESCE(NULLIF(rn.Uploaded_By_Name, ''), NULLIF(rn.Uploaded_By, ''), 'System') AS uploaded_by_display,

          rn.Uploaded_At_Utc AS uploaded_at_utc,

          COUNT(*) AS total_rows,

          -- ✅ FIX: Always return a status for UI grid
          CASE
            -- If header has a value, use it
            WHEN NULLIF(LTRIM(RTRIM(COALESCE(h.Report_Status,''))), '') IS NOT NULL
              THEN LTRIM(RTRIM(h.Report_Status))

            -- Otherwise compute from detail row dq statuses
            WHEN SUM(CASE WHEN LOWER(d.DQ_Status) = 'failed' THEN 1 ELSE 0 END) > 0 THEN 'Failed'

            WHEN COUNT(*) > 0
              AND SUM(CASE WHEN LOWER(d.DQ_Status) = 'approved' THEN 1 ELSE 0 END) = COUNT(*)
              THEN 'Approved'

            WHEN COUNT(*) > 0
              AND SUM(CASE WHEN LOWER(d.DQ_Status) = 'passed' THEN 1 ELSE 0 END) = COUNT(*)
              THEN 'Passed'

            WHEN SUM(CASE WHEN LOWER(d.DQ_Status) = 'validated' THEN 1 ELSE 0 END) > 0 THEN 'Validated'

            WHEN SUM(CASE WHEN LOWER(d.DQ_Status) IN ('new','staged','submitted') THEN 1 ELSE 0 END) > 0
              THEN 'In Progress'

            ELSE 'Pending'
          END AS report_status,

          SUM(CASE WHEN LOWER(d.DQ_Status) = 'passed' THEN 1 ELSE 0 END) AS passed_count,
          SUM(CASE WHEN LOWER(d.DQ_Status) = 'failed' THEN 1 ELSE 0 END) AS failed_count,
          SUM(CASE WHEN LOWER(d.DQ_Status) = 'approved' THEN 1 ELSE 0 END) AS approved_count,

          SUM(CAST(d.Purchase_Dollars_Calc AS FLOAT)) AS total_purchase,
          SUM(CAST(d.CAF_Dollars AS FLOAT)) AS total_caf

        FROM Cur_Invoice_Header h
        JOIN Cur_Invoice_Detail d ON d.Report_Number = h.Report_Number
        JOIN Report_Number rn ON rn.Report_Number = h.Report_Number
        ${whereClause}
        GROUP BY
          h.Report_Number,
          rn.Report_Type,
          rn.Filename,
          rn.Uploaded_By,
          rn.Uploaded_By_Name,
          rn.Uploaded_At_Utc,
          h.Report_Status
      )
      SELECT *
      FROM base
      ORDER BY ${sortField} ${sortOrder}
      OFFSET @p${idx} ROWS FETCH NEXT @p${idx + 1} ROWS ONLY;
    `;

    const { rows } = await query(sql, [...values, offset, pageSize]);

    /* --------------------------------------------------
       Count query (mirrors filters exactly)
    -------------------------------------------------- */
    const countSql = `
      SELECT COUNT(*) AS total FROM (
        SELECT h.Report_Number
        FROM Cur_Invoice_Header h
        JOIN Cur_Invoice_Detail d ON d.Report_Number = h.Report_Number
        JOIN Report_Number rn ON rn.Report_Number = h.Report_Number
        ${whereClause}
        GROUP BY h.Report_Number
      ) t;
    `;
    const countResult = await query(countSql, values);

    res.json({
      reports: rows,
      total: countResult.rows[0]?.total || 0,
      page: pageNum,
      limit: pageSize,
    });
  } catch (err) {
    console.error("❌ SSP reports error:", err);
    res.status(500).json({ error: "Failed to load SSP reports" });
  }
});

/* ======================================================================
   DOWNLOAD VRF DETAIL CSV
====================================================================== */
router.get(
  "/ssp/reports/:report_number/download",
  requireInternalAuth,
  async (req, res) => {
    try {
      const { report_number } = req.params;

      const { rows } = await query(
        `SELECT * FROM Cur_Invoice_Detail WHERE Report_Number=@p1`,
        [report_number]
      );

      if (!rows.length) {
        return res.status(404).json({ error: "Report not found" });
      }

      const escapeCsv = (v) =>
        `"${String(v ?? "")
          .replace(/"/g, '""')
          .replace(/\n/g, " ")}"`;

      const headers = Object.keys(rows[0]).join(",");
      const body = rows
        .map((r) => Object.values(r).map(escapeCsv).join(","))
        .join("\n");

      res.setHeader("Content-Type", "text/csv");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename=vrf_report_${report_number}.csv`
      );

      res.send(`${headers}\n${body}`);
    } catch (err) {
      console.error("❌ VRF CSV error:", err);
      res.status(500).json({ error: "Failed to download report CSV" });
    }
  }
);

export default router;
