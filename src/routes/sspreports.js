// routes/sspreports.js
import express from "express";
import { query } from "../db.js";
import { requireInternalAuth } from "../middleware/auth.js";

const router = express.Router();

/**
 * GET /api/ssp/reports
 * Enhanced SSP Dashboard API
 * - Filters by Supplier, Contract, Member
 * - Totals: Purchase$, CAF$
 * - Counts: Passed, Failed, Approved
 * - Report status
 */
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

    const pageNum = parseInt(page, 10) || 1;
    const pageSize = parseInt(limit, 10) || 25;
    const offset = (pageNum - 1) * pageSize;

    const validSortFields = [
      "report_number",
      "report_type",
      "file_name",
      "uploaded_by",
      "uploaded_at_utc",
      "passed_count",
      "failed_count",
      "approved_count",
      "total_purchase",
      "total_caf",
      "report_status",
    ];

    const sortField = validSortFields.includes(sort) ? sort : "uploaded_at_utc";

    const sortOrder = order === "asc" ? "ASC" : "DESC";

    const conditions = [];
    const values = [];
    let idx = 1;

    // Global search
    if (search) {
      conditions.push(`
        (CAST(h.Report_Number AS NVARCHAR(50)) LIKE @p${idx}
        OR rn.Filename LIKE @p${idx}
        OR rn.Uploaded_By LIKE @p${idx})
      `);
      values.push(`%${search}%`);
      idx++;
    }

    // Filter by supplier (bp_code)
    if (supplier) {
      conditions.push(`h.BP_Code = @p${idx}`);
      values.push(supplier);
      idx++;
    }

    // Filter by contract
    if (contract) {
      conditions.push(`h.Contract_ID = @p${idx}`);
      values.push(contract);
      idx++;
    }

    // Filter by member
    if (member) {
      conditions.push(`d.Member_Number LIKE @p${idx}`);
      values.push(`%${member}%`);
      idx++;
    }

    // Date filters
    if (startDate && endDate) {
      const dateColumn =
        dateType === "Approved_At_Utc"
          ? "h.Approved_At_Utc"
          : "rn.Uploaded_At_Utc";

      conditions.push(`${dateColumn} BETWEEN @p${idx} AND @p${idx + 1}`);
      values.push(startDate, endDate);
      idx += 2;
    }

    const whereClause =
      conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    // Main query
    const queryStr = `
      WITH base AS (
        SELECT
          h.Report_Number AS report_number,
          rn.Report_Type AS report_type,
          rn.Filename AS file_name,
          rn.Uploaded_By AS uploaded_by,
          rn.Uploaded_At_Utc AS uploaded_at_utc,
          h.Report_Status AS report_status,

          SUM(CASE WHEN d.DQ_Status = 'PASSED' THEN 1 ELSE 0 END) AS passed_count,
          SUM(CASE WHEN d.DQ_Status = 'FAILED' THEN 1 ELSE 0 END) AS failed_count,
          SUM(CASE WHEN d.DQ_Status = 'approved' THEN 1 ELSE 0 END) AS approved_count,

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
          rn.Uploaded_At_Utc,
          h.Report_Status
      )
      SELECT *
      FROM base
      ORDER BY ${sortField} ${sortOrder}
      OFFSET @p${idx} ROWS FETCH NEXT @p${idx + 1} ROWS ONLY;
    `;

    const results = await query(queryStr, [...values, offset, pageSize]);

    // Count for pagination
    const countQuery = `
      SELECT COUNT(*) AS total FROM (
        SELECT h.Report_Number
        FROM Cur_Invoice_Header h
        JOIN Cur_Invoice_Detail d ON d.Report_Number = h.Report_Number
        JOIN Report_Number rn ON rn.Report_Number = h.Report_Number
        ${whereClause}
        GROUP BY h.Report_Number
      ) AS t;
    `;
    const countResult = await query(countQuery, values);

    res.json({
      reports: results.rows,
      total: countResult.rows[0].total,
      page: pageNum,
      limit: pageSize,
    });
  } catch (err) {
    console.error("❌ Error:", err);
    res.status(500).json({ error: "Failed to load SSP reports." });
  }
});

/**
 * Download full VRF detail CSV for a report
 */
router.get(
  "/ssp/reports/:report_number/download",
  requireInternalAuth,
  async (req, res) => {
    try {
      const { report_number } = req.params;

      const detailQuery = `
        SELECT *
        FROM Cur_Invoice_Detail
        WHERE Report_Number = @p1
      `;
      const result = await query(detailQuery, [report_number]);

      if (result.rows.length === 0) {
        return res.status(404).json({ error: "Report not found." });
      }

      // Build CSV
      const headers = Object.keys(result.rows[0]).join(",");
      const rows = result.rows
        .map((row) =>
          Object.values(row)
            .map((v) => `"${v ?? ""}"`)
            .join(",")
        )
        .join("\n");

      const csv = `${headers}\n${rows}`;

      res.setHeader("Content-Type", "text/csv");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename=vrf_report_${report_number}.csv`
      );

      res.send(csv);
    } catch (err) {
      console.error("❌ CSV download error:", err);
      res.status(500).json({ error: "Failed to download report CSV." });
    }
  }
);

export default router;
