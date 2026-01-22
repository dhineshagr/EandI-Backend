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
      statuses = "", // optional CSV: approved,failed,passed,submitted
      sort = "uploaded_at_utc",
      order = "desc",
      page = 1,
      limit = 25,
    } = req.query;

    const pageNum = Number(page) || 1;
    const pageSize = Number(limit) || 25;
    const offset = (pageNum - 1) * pageSize;

    // --------------------------------------------------
    // Sorting whitelist (MUST match selected columns)
    // --------------------------------------------------
    const validSortFields = [
      "report_number",
      "report_type",
      "file_name",
      "uploaded_by_display",
      "uploaded_at_utc",
      "report_status",
      "passed_count",
      "failed_count",
      "approved_count",
      "total_purchase",
      "total_caf",
    ];

    const sortField = validSortFields.includes(sort) ? sort : "uploaded_at_utc";
    const sortOrder = String(order).toLowerCase() === "asc" ? "ASC" : "DESC";

    // --------------------------------------------------
    // Filters
    // --------------------------------------------------
    const conditions = [];
    const values = [];
    let idx = 1;

    if (search) {
      conditions.push(`
        (
          CAST(rn.Report_Number AS NVARCHAR(50)) LIKE @p${idx}
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

    // member filter requires detail rows; will naturally exclude zero-sales
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

    const whereClause = conditions.length
      ? `WHERE ${conditions.join(" AND ")}`
      : "";

    // --------------------------------------------------
    // statuses filter (applied on derived status)
    // --------------------------------------------------
    const statusList = String(statuses || "")
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);

    // We'll apply this AFTER we compute report_status in the CTE
    const statusFilterSql =
      statusList.length > 0
        ? `WHERE base.report_status IN (${statusList
            .map((_, i) => `@p${idx + i}`)
            .join(", ")})`
        : "";

    const statusFilterValuesStartIdx = idx;
    if (statusList.length > 0) {
      values.push(...statusList);
      idx += statusList.length;
    }

    // --------------------------------------------------
    // MAIN QUERY
    // IMPORTANT: use ;WITH so SQL Server accepts CTE safely
    // --------------------------------------------------
    const sql = `
      ;WITH base AS (
        SELECT
          rn.Report_Number AS report_number,
          rn.Report_Type   AS report_type,
          rn.Filename      AS file_name,

          rn.Uploaded_By        AS uploaded_by,
          rn.Uploaded_By_Name   AS uploaded_by_name,
          COALESCE(NULLIF(rn.Uploaded_By_Name, ''), NULLIF(rn.Uploaded_By, ''), 'System') AS uploaded_by_display,

          rn.Uploaded_At_Utc AS uploaded_at_utc,

          -- counts (0 when no detail rows)
          SUM(CASE WHEN LOWER(COALESCE(d.DQ_Status,'')) = 'passed' THEN 1 ELSE 0 END) AS passed_count,
          SUM(CASE WHEN LOWER(COALESCE(d.DQ_Status,'')) = 'failed' THEN 1 ELSE 0 END) AS failed_count,
          SUM(CASE WHEN LOWER(COALESCE(d.DQ_Status,'')) = 'approved' THEN 1 ELSE 0 END) AS approved_count,

          COALESCE(SUM(CAST(d.Purchase_Dollars_Calc AS FLOAT)), 0) AS total_purchase,
          COALESCE(SUM(CAST(d.CAF_Dollars AS FLOAT)), 0) AS total_caf,

          LOWER(
            CASE
              -- approved can be driven by header OR report_number lifecycle
              WHEN LOWER(COALESCE(NULLIF(h.Report_Status,''),'')) = 'approved'
                   OR LOWER(COALESCE(NULLIF(rn.Status,''),'')) = 'approved'
                THEN 'approved'

              -- any failed detail -> failed
              WHEN SUM(CASE WHEN LOWER(COALESCE(d.DQ_Status,'')) = 'failed' THEN 1 ELSE 0 END) > 0
                THEN 'failed'

              -- has details and no failed -> passed
              WHEN COUNT(d.Report_Number) > 0
                   AND SUM(CASE WHEN LOWER(COALESCE(d.DQ_Status,'')) = 'failed' THEN 1 ELSE 0 END) = 0
                THEN 'passed'

              -- submitted = new/staged
              WHEN LOWER(COALESCE(NULLIF(rn.Status,''),'')) IN ('new','staged')
                THEN 'submitted'

              -- fallback (avoid "pending" in SSP dashboard)
              ELSE COALESCE(NULLIF(LOWER(rn.Status),''), 'submitted')
            END
          ) AS report_status

        FROM Report_Number rn
        LEFT JOIN Cur_Invoice_Header h ON h.Report_Number = rn.Report_Number
        LEFT JOIN Cur_Invoice_Detail d ON d.Report_Number = rn.Report_Number
        ${whereClause}
        GROUP BY
          rn.Report_Number,
          rn.Report_Type,
          rn.Filename,
          rn.Uploaded_By,
          rn.Uploaded_By_Name,
          rn.Uploaded_At_Utc,
          rn.Status,
          h.Report_Status
      )
      SELECT *
      FROM base
      ${statusFilterSql}
      ORDER BY ${sortField} ${sortOrder}
      OFFSET @p${idx} ROWS FETCH NEXT @p${idx + 1} ROWS ONLY;
    `;

    const { rows } = await query(sql, [...values, offset, pageSize]);

    // --------------------------------------------------
    // COUNT QUERY: must mirror same logic + filters
    // --------------------------------------------------
    // Rebuild values for count (same values up to status filter)
    const countValues = [...values]; // includes statusList if provided
    // Remove paging params for count: (offset,pageSize) not needed
    // We did NOT add them to countValues, so nothing to remove.

    const countSql = `
      ;WITH base AS (
        SELECT
          rn.Report_Number AS report_number,
          LOWER(
            CASE
              WHEN LOWER(COALESCE(NULLIF(h.Report_Status,''),'')) = 'approved'
                   OR LOWER(COALESCE(NULLIF(rn.Status,''),'')) = 'approved'
                THEN 'approved'
              WHEN SUM(CASE WHEN LOWER(COALESCE(d.DQ_Status,'')) = 'failed' THEN 1 ELSE 0 END) > 0
                THEN 'failed'
              WHEN COUNT(d.Report_Number) > 0
                   AND SUM(CASE WHEN LOWER(COALESCE(d.DQ_Status,'')) = 'failed' THEN 1 ELSE 0 END) = 0
                THEN 'passed'
              WHEN LOWER(COALESCE(NULLIF(rn.Status,''),'')) IN ('new','staged')
                THEN 'submitted'
              ELSE COALESCE(NULLIF(LOWER(rn.Status),''), 'submitted')
            END
          ) AS report_status
        FROM Report_Number rn
        LEFT JOIN Cur_Invoice_Header h ON h.Report_Number = rn.Report_Number
        LEFT JOIN Cur_Invoice_Detail d ON d.Report_Number = rn.Report_Number
        ${whereClause}
        GROUP BY rn.Report_Number, rn.Status, h.Report_Status
      )
      SELECT COUNT(*) AS total
      FROM base
      ${
        statusList.length > 0
          ? `WHERE base.report_status IN (${statusList
              .map((_, i) => `@p${statusFilterValuesStartIdx + i}`)
              .join(", ")})`
          : ""
      };
    `;

    const countResult = await query(countSql, countValues);

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
