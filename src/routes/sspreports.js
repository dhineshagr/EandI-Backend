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
// routes/sspreports.js

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
      statuses = "",
      sort = "uploaded_at_utc",
      order = "desc",
      page = 1,
      limit = 25,
    } = req.query;

    // ================================================================
    // PAGINATION
    // ================================================================
    const pageNum = Math.max(1, Number(page) || 1);
    const pageSize = Math.min(100, Math.max(1, Number(limit) || 25));
    const offset = (pageNum - 1) * pageSize;

    // ================================================================
    // SORTING
    // ================================================================
    const validSortFields = [
      "report_number",
      "related_report_number",
      "report_type",
      "file_name",
      "uploaded_by_display",
      "uploaded_at_utc",
      "report_status",
      "period",
      "supplier_name",
      "bp_code",
      "contract_id",
      "passed_count",
      "failed_count",
      "approved_count",
      "total_purchase",
      "total_caf",
    ];

    const sortField = validSortFields.includes(sort) ? sort : "uploaded_at_utc";

    const sortOrder = String(order).toLowerCase() === "asc" ? "ASC" : "DESC";

    // ================================================================
    // QUERY PARAMETERS
    // ================================================================
    const conditions = [];
    const values = [];
    let idx = 1;

    // ================================================================
    // GENERAL SEARCH
    // ================================================================
    if (search) {
      conditions.push(`
        (
          CAST(rn.Report_Number AS NVARCHAR(50)) LIKE @p${idx}
          OR CAST(
            rn.Related_Report_Number AS NVARCHAR(50)
          ) LIKE @p${idx}
          OR rn.Filename LIKE @p${idx}
          OR rn.Uploaded_By LIKE @p${idx}
          OR rn.Uploaded_By_Name LIKE @p${idx}
          OR rn.Period LIKE @p${idx}
          OR period_data.selected_periods LIKE @p${idx}
          OR rn.BP_Code LIKE @p${idx}
          OR s.Supplier_Name LIKE @p${idx}
          OR CAST(
            rn.Contract_ID AS NVARCHAR(100)
          ) LIKE @p${idx}
        )
      `);

      values.push(`%${search}%`);
      idx++;
    }

    // ================================================================
    // SUPPLIER FILTER
    // ================================================================
    if (supplier) {
      conditions.push(`
        (
          rn.BP_Code LIKE @p${idx}
          OR s.Supplier_Name LIKE @p${idx}
        )
      `);

      values.push(`%${supplier}%`);
      idx++;
    }

    // ================================================================
    // CONTRACT FILTER
    // ================================================================
    if (contract) {
      conditions.push(`
        CAST(rn.Contract_ID AS NVARCHAR(100)) LIKE @p${idx}
      `);

      values.push(`%${contract}%`);
      idx++;
    }

    // ================================================================
    // MEMBER FILTER
    // ================================================================
    if (member) {
      conditions.push(`
        EXISTS (
          SELECT 1
          FROM Cur_Invoice_Detail member_detail
          WHERE member_detail.Report_Number = rn.Report_Number
            AND (
              member_detail.Member_Number LIKE @p${idx}
              OR member_detail.Member_Name LIKE @p${idx}
            )
        )
      `);

      values.push(`%${member}%`);
      idx++;
    }

    // ================================================================
    // DATE FILTER
    // ================================================================
    if (startDate || endDate) {
      const dateColumn =
        dateType === "Approved_At_Utc"
          ? "h.Approved_At_Utc"
          : "rn.Uploaded_At_Utc";

      if (startDate) {
        conditions.push(`${dateColumn} >= @p${idx}`);
        values.push(startDate);
        idx++;
      }

      if (endDate) {
        /*
         * Includes the complete selected end date.
         *
         * Example:
         * endDate = 2026-07-24
         * Includes values before 2026-07-25 00:00:00.
         */
        conditions.push(`
          ${dateColumn} < DATEADD(DAY, 1, @p${idx})
        `);

        values.push(endDate);
        idx++;
      }
    }

    const whereClause =
      conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    // ================================================================
    // STATUS FILTER
    // ================================================================
    const statusList = String(statuses || "")
      .split(",")
      .map((status) => status.trim().toLowerCase())
      .filter(Boolean);

    const statusFilterParams = statusList.map(
      (_, statusIndex) => `@p${idx + statusIndex}`,
    );

    const statusFilterSql =
      statusList.length > 0
        ? `
          WHERE base.report_status IN (
            ${statusFilterParams.join(", ")}
          )
        `
        : "";

    if (statusList.length > 0) {
      values.push(...statusList);
      idx += statusList.length;
    }

    // ================================================================
    // SHARED BASE QUERY
    // ================================================================
    const baseCte = `
      ;WITH base AS (
        SELECT
          rn.Report_Number AS report_number,
          rn.Related_Report_Number AS related_report_number,
          rn.Report_Type AS report_type,
          rn.Filename AS file_name,

          COALESCE(
            NULLIF(period_data.selected_periods, ''),
            NULLIF(rn.Period, '')
          ) AS period,

          rn.BP_Code AS bp_code,
          s.Supplier_Name AS supplier_name,
          rn.Contract_ID AS contract_id,

          rn.Uploaded_By AS uploaded_by,
          rn.Uploaded_By_Name AS uploaded_by_name,

          COALESCE(
            NULLIF(rn.Uploaded_By_Name, ''),
            NULLIF(rn.Uploaded_By, ''),
            'System'
          ) AS uploaded_by_display,

          rn.Uploaded_At_Utc AS uploaded_at_utc,

          COUNT(d.Cur_Detail_ID) AS total_rows,

          SUM(
            CASE
              WHEN LOWER(
                COALESCE(d.DQ_Status, '')
              ) = 'passed'
                THEN 1
              ELSE 0
            END
          ) AS passed_count,

          SUM(
            CASE
              WHEN LOWER(
                COALESCE(d.DQ_Status, '')
              ) = 'failed'
                THEN 1
              ELSE 0
            END
          ) AS failed_count,

          SUM(
            CASE
              WHEN LOWER(
                COALESCE(d.DQ_Status, '')
              ) = 'approved'
                THEN 1
              ELSE 0
            END
          ) AS approved_count,

          COALESCE(
            SUM(
              TRY_CAST(
                d.Purchase_Dollars_Calc AS DECIMAL(19, 2)
              )
            ),
            0
          ) AS total_purchase,

          COALESCE(
            SUM(
              TRY_CAST(
                d.CAF_Dollars AS DECIMAL(19, 2)
              )
            ),
            0
          ) AS total_caf,

          LOWER(
            CASE
              -- Zero Sales records do not have detail rows.
              WHEN UPPER(
                LTRIM(RTRIM(rn.Filename))
              ) = 'ZERO_SALES'
                OR UPPER(
                  LTRIM(RTRIM(rn.Filename))
                ) LIKE 'ZERO_SALES%'
                THEN 'submitted'

              -- Header or Report Number status is approved.
              WHEN LOWER(
                COALESCE(
                  NULLIF(h.Report_Status, ''),
                  ''
                )
              ) = 'approved'
                OR LOWER(
                  COALESCE(
                    NULLIF(rn.Status, ''),
                    ''
                  )
                ) = 'approved'
                THEN 'approved'

              -- At least one detail row failed.
              WHEN SUM(
                CASE
                  WHEN LOWER(
                    COALESCE(d.DQ_Status, '')
                  ) = 'failed'
                    THEN 1
                  ELSE 0
                END
              ) > 0
                THEN 'failed'

              -- All detail rows are approved.
              WHEN COUNT(d.Cur_Detail_ID) > 0
                AND SUM(
                  CASE
                    WHEN LOWER(
                      COALESCE(d.DQ_Status, '')
                    ) = 'approved'
                      THEN 1
                    ELSE 0
                  END
                ) = COUNT(d.Cur_Detail_ID)
                THEN 'approved'

              -- Detail rows exist and none failed.
              WHEN COUNT(d.Cur_Detail_ID) > 0
                AND SUM(
                  CASE
                    WHEN LOWER(
                      COALESCE(d.DQ_Status, '')
                    ) = 'failed'
                      THEN 1
                    ELSE 0
                  END
                ) = 0
                THEN 'passed'

              -- Processing-like statuses.
              WHEN LOWER(
                COALESCE(
                  NULLIF(rn.Status, ''),
                  ''
                )
              ) IN (
                'new',
                'staged',
                'pending',
                'submitted'
              )
                THEN 'submitted'

              -- Default status.
              ELSE COALESCE(
                NULLIF(LOWER(rn.Status), ''),
                'submitted'
              )
            END
          ) AS report_status

        FROM Report_Number rn

        LEFT JOIN Ref_Supplier s
          ON s.BP_Code = rn.BP_Code

        LEFT JOIN Cur_Invoice_Header h
          ON h.Report_Number = rn.Report_Number

        LEFT JOIN Cur_Invoice_Detail d
          ON d.Report_Number = rn.Report_Number

        OUTER APPLY (
          SELECT
            STRING_AGG(
              CAST(
                period_rows.Period AS NVARCHAR(50)
              ),
              ', '
            ) AS selected_periods
          FROM (
            SELECT DISTINCT
              rp.Period
            FROM Report_Period rp
            WHERE rp.Report_Number = rn.Report_Number
              AND rp.Period IS NOT NULL
          ) period_rows
        ) period_data

        ${whereClause}

        GROUP BY
          rn.Report_Number,
          rn.Related_Report_Number,
          rn.Report_Type,
          rn.Filename,
          rn.Period,
          period_data.selected_periods,
          rn.BP_Code,
          s.Supplier_Name,
          rn.Contract_ID,
          rn.Uploaded_By,
          rn.Uploaded_By_Name,
          rn.Uploaded_At_Utc,
          rn.Status,
          h.Report_Status
      )
    `;

    // ================================================================
    // CURRENT PAGE DATA QUERY
    // ================================================================
    const dataSql = `
      ${baseCte}

      SELECT *
      FROM base
      ${statusFilterSql}
      ORDER BY ${sortField} ${sortOrder}
      OFFSET @p${idx} ROWS
      FETCH NEXT @p${idx + 1} ROWS ONLY;
    `;

    const { rows } = await query(dataSql, [...values, offset, pageSize]);

    // ================================================================
    // FILTERED RECORD COUNT
    // ================================================================
    const countSql = `
      ${baseCte}

      SELECT COUNT(*) AS total
      FROM base
      ${statusFilterSql};
    `;

    const countResult = await query(countSql, values);

    // ================================================================
    // FORMAT REPORT RESPONSE
    // ================================================================
    const reports = rows.map((report) => {
      const periods = String(report.period || "")
        .split(",")
        .map((periodValue) => periodValue.trim())
        .filter(Boolean);

      return {
        ...report,
        periods,
      };
    });

    // ================================================================
    // CURRENT PAGE TOTALS
    //
    // These totals use only the records returned for this page.
    //
    // Example:
    // Page contains 20 reports => totals for those 20 reports.
    // Filter returns 5 reports => totals for those 5 reports.
    // ================================================================
    const pageTotals = reports.reduce(
      (totals, report) => {
        const purchaseValue = Number(report.total_purchase || 0);

        const cafValue = Number(report.total_caf || 0);

        totals.total_purchase += Number.isFinite(purchaseValue)
          ? purchaseValue
          : 0;

        totals.total_caf += Number.isFinite(cafValue) ? cafValue : 0;

        return totals;
      },
      {
        total_purchase: 0,
        total_caf: 0,
      },
    );

    // Keep money values rounded to two decimal places.
    const formattedPageTotals = {
      record_count: reports.length,
      total_purchase: Number(pageTotals.total_purchase.toFixed(2)),
      total_caf: Number(pageTotals.total_caf.toFixed(2)),
    };

    // ================================================================
    // RESPONSE
    // ================================================================
    res.json({
      reports,

      total: Number(countResult.rows[0]?.total || 0),

      page: pageNum,
      limit: pageSize,

      page_totals: formattedPageTotals,
    });
  } catch (err) {
    console.error("❌ SSP reports error:", err);

    res.status(500).json({
      error: "Failed to load SSP reports",
    });
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
        [report_number],
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
        `attachment; filename=vrf_report_${report_number}.csv`,
      );

      res.send(`${headers}\n${body}`);
    } catch (err) {
      console.error("❌ VRF CSV error:", err);
      res.status(500).json({ error: "Failed to download report CSV" });
    }
  },
);

export default router;
