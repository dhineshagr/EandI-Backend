// routes/sspreports.js
import express from "express";
import { query } from "../db.js";
import { requireInternalAuth } from "../middleware/auth.js";

const router = express.Router();

/* ======================================================================
   CSV HELPERS
====================================================================== */

const escapeCsv = (value) =>
  `"${String(value ?? "")
    .replace(/"/g, '""')
    .replace(/\r?\n/g, " ")}"`;

const formatCsvNumber = (value) => {
  const numericValue = Number(value);

  return Number.isFinite(numericValue) ? numericValue.toFixed(2) : "0.00";
};
/* ======================================================================
   GET /api/ssp/reports
   SSP Reports Dashboard

   Client requirement:
   - Display only fully approved reports.
   - Report header/status must be approved.
   - Report must contain detail rows.
   - Every detail row must have DQ_Status = approved.
====================================================================== */

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

    const sortOrder =
      String(order || "")
        .trim()
        .toLowerCase() === "asc"
        ? "ASC"
        : "DESC";

    // ================================================================
    // QUERY PARAMETERS
    // ================================================================

    const conditions = [];
    const values = [];

    let idx = 1;

    // ================================================================
    // GENERAL SEARCH
    // ================================================================

    const normalizedSearch = String(search || "").trim();

    if (normalizedSearch) {
      conditions.push(`
        (
          CAST(rn.Report_Number AS NVARCHAR(50)) LIKE @p${idx}

          OR CAST(
            rn.Related_Report_Number AS NVARCHAR(50)
          ) LIKE @p${idx}

          OR rn.FileName LIKE @p${idx}

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

      values.push(`%${normalizedSearch}%`);

      idx++;
    }

    // ================================================================
    // SUPPLIER FILTER
    // ================================================================

    const normalizedSupplier = String(supplier || "").trim();

    if (normalizedSupplier) {
      conditions.push(`
        (
          rn.BP_Code LIKE @p${idx}
          OR s.Supplier_Name LIKE @p${idx}
        )
      `);

      values.push(`%${normalizedSupplier}%`);

      idx++;
    }

    // ================================================================
    // CONTRACT FILTER
    // ================================================================

    const normalizedContract = String(contract || "").trim();

    if (normalizedContract) {
      conditions.push(`
        CAST(
          rn.Contract_ID AS NVARCHAR(100)
        ) LIKE @p${idx}
      `);

      values.push(`%${normalizedContract}%`);

      idx++;
    }

    // ================================================================
    // MEMBER FILTER
    // ================================================================

    const normalizedMember = String(member || "").trim();

    if (normalizedMember) {
      conditions.push(`
        EXISTS
        (
          SELECT 1
          FROM dbo.Cur_Invoice_Detail member_detail
          WHERE member_detail.Report_Number = rn.Report_Number
            AND
            (
              member_detail.Member_Number LIKE @p${idx}
              OR member_detail.Member_Name LIKE @p${idx}
            )
        )
      `);

      values.push(`%${normalizedMember}%`);

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
         * Include the complete selected end date.
         *
         * Example:
         * endDate = 2026-07-27
         * Includes records before 2026-07-28 00:00:00.
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
    // OPTIONAL STATUS FILTER
    //
    // The SSP Dashboard now contains only approved reports.
    // This parameter is preserved for compatibility with existing calls.
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
          WHERE base.report_status IN
          (
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
    //
    // Important:
    // The HAVING clause restricts this dashboard to fully approved
    // reports only.
    // ================================================================

    const baseCte = `
      ;WITH base AS
      (
        SELECT
          rn.Report_Number AS report_number,

          rn.Related_Report_Number AS related_report_number,

          rn.Report_Type AS report_type,

          rn.FileName AS file_name,

          COALESCE
          (
            NULLIF(period_data.selected_periods, ''),
            NULLIF(rn.Period, '')
          ) AS period,

          rn.BP_Code AS bp_code,

          s.Supplier_Name AS supplier_name,

          rn.Contract_ID AS contract_id,

          rn.Uploaded_By AS uploaded_by,

          rn.Uploaded_By_Name AS uploaded_by_name,

          COALESCE
          (
            NULLIF(rn.Uploaded_By_Name, ''),
            NULLIF(rn.Uploaded_By, ''),
            'System'
          ) AS uploaded_by_display,

          rn.Uploaded_At_Utc AS uploaded_at_utc,

          COUNT(d.Cur_Detail_ID) AS total_rows,

          SUM
          (
            CASE
              WHEN LOWER
              (
                LTRIM
                (
                  RTRIM
                  (
                    COALESCE(d.DQ_Status, '')
                  )
                )
              ) = 'passed'
                THEN 1
              ELSE 0
            END
          ) AS passed_count,

          SUM
          (
            CASE
              WHEN LOWER
              (
                LTRIM
                (
                  RTRIM
                  (
                    COALESCE(d.DQ_Status, '')
                  )
                )
              ) = 'failed'
                THEN 1
              ELSE 0
            END
          ) AS failed_count,

          SUM
          (
            CASE
              WHEN LOWER
              (
                LTRIM
                (
                  RTRIM
                  (
                    COALESCE(d.DQ_Status, '')
                  )
                )
              ) = 'approved'
                THEN 1
              ELSE 0
            END
          ) AS approved_count,

          COALESCE
          (
            SUM
            (
              TRY_CAST
              (
                d.Purchase_Dollars_Calc AS DECIMAL(19, 2)
              )
            ),
            0
          ) AS total_purchase,

          COALESCE
          (
            SUM
            (
              TRY_CAST
              (
                d.CAF_Dollars AS DECIMAL(19, 2)
              )
            ),
            0
          ) AS total_caf,

          CAST('approved' AS NVARCHAR(20)) AS report_status

        FROM dbo.Report_Number rn

        LEFT JOIN dbo.Ref_Supplier s
          ON s.BP_Code = rn.BP_Code

        LEFT JOIN dbo.Cur_Invoice_Header h
          ON h.Report_Number = rn.Report_Number

        LEFT JOIN dbo.Cur_Invoice_Detail d
          ON d.Report_Number = rn.Report_Number

        OUTER APPLY
        (
          SELECT
            STRING_AGG
            (
              CAST(period_rows.Period AS NVARCHAR(50)),
              ', '
            ) AS selected_periods

          FROM
          (
            SELECT DISTINCT
              rp.Period

            FROM dbo.Report_Period rp

            WHERE rp.Report_Number = rn.Report_Number

              AND rp.Period IS NOT NULL

              AND LTRIM
              (
                RTRIM
                (
                  CAST(rp.Period AS NVARCHAR(50))
                )
              ) <> ''
          ) period_rows
        ) period_data

        ${whereClause}

        GROUP BY
          rn.Report_Number,
          rn.Related_Report_Number,
          rn.Report_Type,
          rn.FileName,
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

        HAVING
          /*
           * The report header or main report status must be approved.
           */
          LOWER
          (
            LTRIM
            (
              RTRIM
              (
                COALESCE
                (
                  NULLIF(h.Report_Status, ''),
                  NULLIF(rn.Status, ''),
                  ''
                )
              )
            )
          ) = 'approved'

          /*
           * The report must contain at least one detail row.
           */
          AND COUNT(d.Cur_Detail_ID) > 0

          /*
           * Every detail row must be approved.
           */
          AND SUM
          (
            CASE
              WHEN LOWER
              (
                LTRIM
                (
                  RTRIM
                  (
                    COALESCE(d.DQ_Status, '')
                  )
                )
              ) = 'approved'
                THEN 1
              ELSE 0
            END
          ) = COUNT(d.Cur_Detail_ID)
      )
    `;

    // ================================================================
    // CURRENT PAGE DATA QUERY
    // ================================================================

    const dataSql = `
      ${baseCte}

      SELECT
        base.report_number,
        base.related_report_number,
        base.report_type,
        base.file_name,
        base.period,
        base.bp_code,
        base.supplier_name,
        base.contract_id,
        base.uploaded_by,
        base.uploaded_by_name,
        base.uploaded_by_display,
        base.uploaded_at_utc,
        base.total_rows,
        base.passed_count,
        base.failed_count,
        base.approved_count,
        base.total_purchase,
        base.total_caf,
        base.report_status

      FROM base

      ${statusFilterSql}

      ORDER BY ${sortField} ${sortOrder}

      OFFSET @p${idx} ROWS

      FETCH NEXT @p${idx + 1} ROWS ONLY;
    `;

    const dataParams = [...values, offset, pageSize];

    const { rows } = await query(dataSql, dataParams);

    // ================================================================
    // FILTERED RECORD COUNT
    // ================================================================

    const countSql = `
      ${baseCte}

      SELECT
        COUNT(*) AS total

      FROM base

      ${statusFilterSql};
    `;

    const countResult = await query(countSql, values);

    // ================================================================
    // FORMAT REPORT RESPONSE
    // ================================================================

    const reports = (rows || []).map((report) => {
      const periods = String(report.period || "")
        .split(",")
        .map((periodValue) => periodValue.trim())
        .filter(Boolean);

      return {
        ...report,

        periods,

        total_rows: Number(report.total_rows || 0),

        passed_count: Number(report.passed_count || 0),

        failed_count: Number(report.failed_count || 0),

        approved_count: Number(report.approved_count || 0),

        total_purchase: Number(report.total_purchase || 0),

        total_caf: Number(report.total_caf || 0),

        report_status: "approved",
      };
    });

    // ================================================================
    // CURRENT PAGE TOTALS
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

    const formattedPageTotals = {
      record_count: reports.length,

      total_purchase: Number(pageTotals.total_purchase.toFixed(2)),

      total_caf: Number(pageTotals.total_caf.toFixed(2)),
    };

    // ================================================================
    // RESPONSE
    // ================================================================

    return res.status(200).json({
      success: true,

      reports,

      total: Number(countResult.rows?.[0]?.total || 0),

      page: pageNum,

      limit: pageSize,

      page_totals: formattedPageTotals,
    });
  } catch (error) {
    console.error("❌ GET /ssp/reports error:", error);

    return res.status(500).json({
      success: false,

      error: "Failed to load SSP reports",

      code: "SSP_REPORTS_LOAD_FAILED",
    });
  }
});

/* ======================================================================
   DOWNLOAD SSP REPORTS SUMMARY CSV

   GET /api/ssp/reports/export-summary

   Behavior:
   - Uses the same filters as the SSP Reports Dashboard.
   - Includes only fully approved reports.
   - Exports all filtered records without pagination.
   - Appends a TOTAL row for Purchase and CAF.
====================================================================== */

router.get(
  "/ssp/reports/export-summary",
  requireInternalAuth,
  async (req, res) => {
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
      } = req.query;

      // ================================================================
      // SORTING
      // ================================================================

      const validSortFields = [
        "report_number",
        "related_report_number",
        "report_type",
        "file_name",
        "period",
        "supplier_name",
        "bp_code",
        "contract_id",
        "uploaded_by_display",
        "uploaded_at_utc",
        "report_status",
        "passed_count",
        "failed_count",
        "approved_count",
        "total_purchase",
        "total_caf",
      ];

      const sortField = validSortFields.includes(sort)
        ? sort
        : "uploaded_at_utc";

      const sortOrder =
        String(order || "")
          .trim()
          .toLowerCase() === "asc"
          ? "ASC"
          : "DESC";

      // ================================================================
      // FILTERS
      // ================================================================

      const conditions = [];
      const values = [];

      let parameterIndex = 1;

      const normalizedSearch = String(search || "").trim();

      if (normalizedSearch) {
        conditions.push(`
          (
            CAST(rn.Report_Number AS NVARCHAR(50))
              LIKE @p${parameterIndex}

            OR CAST(
              rn.Related_Report_Number AS NVARCHAR(50)
            ) LIKE @p${parameterIndex}

            OR rn.FileName LIKE @p${parameterIndex}

            OR rn.Uploaded_By LIKE @p${parameterIndex}

            OR rn.Uploaded_By_Name LIKE @p${parameterIndex}

            OR rn.Period LIKE @p${parameterIndex}

            OR period_data.selected_periods LIKE @p${parameterIndex}

            OR rn.BP_Code LIKE @p${parameterIndex}

            OR s.Supplier_Name LIKE @p${parameterIndex}

            OR CAST(
              rn.Contract_ID AS NVARCHAR(100)
            ) LIKE @p${parameterIndex}
          )
        `);

        values.push(`%${normalizedSearch}%`);
        parameterIndex++;
      }

      const normalizedSupplier = String(supplier || "").trim();

      if (normalizedSupplier) {
        conditions.push(`
          (
            rn.BP_Code LIKE @p${parameterIndex}
            OR s.Supplier_Name LIKE @p${parameterIndex}
          )
        `);

        values.push(`%${normalizedSupplier}%`);
        parameterIndex++;
      }

      const normalizedContract = String(contract || "").trim();

      if (normalizedContract) {
        conditions.push(`
          CAST(
            rn.Contract_ID AS NVARCHAR(100)
          ) LIKE @p${parameterIndex}
        `);

        values.push(`%${normalizedContract}%`);
        parameterIndex++;
      }

      const normalizedMember = String(member || "").trim();

      if (normalizedMember) {
        conditions.push(`
          EXISTS
          (
            SELECT 1
            FROM dbo.Cur_Invoice_Detail member_detail
            WHERE
              member_detail.Report_Number = rn.Report_Number
              AND
              (
                member_detail.Member_Number
                  LIKE @p${parameterIndex}

                OR member_detail.Member_Name
                  LIKE @p${parameterIndex}

                OR member_detail.Matched_Member_Number
                  LIKE @p${parameterIndex}

                OR member_detail.Matched_Member_Name
                  LIKE @p${parameterIndex}
              )
          )
        `);

        values.push(`%${normalizedMember}%`);
        parameterIndex++;
      }

      if (startDate || endDate) {
        const dateColumn =
          dateType === "Approved_At_Utc"
            ? "h.Approved_At_Utc"
            : "rn.Uploaded_At_Utc";

        if (startDate) {
          conditions.push(`${dateColumn} >= @p${parameterIndex}`);

          values.push(startDate);
          parameterIndex++;
        }

        if (endDate) {
          conditions.push(`
            ${dateColumn}
              < DATEADD(DAY, 1, @p${parameterIndex})
          `);

          values.push(endDate);
          parameterIndex++;
        }
      }

      const whereClause =
        conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

      // ================================================================
      // QUERY
      // ================================================================

      const sql = `
        ;WITH base AS
        (
          SELECT
            rn.Report_Number AS report_number,

            rn.Related_Report_Number
              AS related_report_number,

            rn.Report_Type AS report_type,

            rn.FileName AS file_name,

            COALESCE
            (
              NULLIF(period_data.selected_periods, ''),
              NULLIF(rn.Period, '')
            ) AS period,

            rn.BP_Code AS bp_code,

            s.Supplier_Name AS supplier_name,

            rn.Contract_ID AS contract_id,

            COALESCE
            (
              NULLIF(rn.Uploaded_By_Name, ''),
              NULLIF(rn.Uploaded_By, ''),
              'System'
            ) AS uploaded_by_display,

            rn.Uploaded_At_Utc AS uploaded_at_utc,

            COUNT(d.Cur_Detail_ID) AS total_rows,

            SUM
            (
              CASE
                WHEN LOWER
                (
                  LTRIM
                  (
                    RTRIM
                    (
                      COALESCE(d.DQ_Status, '')
                    )
                  )
                ) = 'passed'
                  THEN 1
                ELSE 0
              END
            ) AS passed_count,

            SUM
            (
              CASE
                WHEN LOWER
                (
                  LTRIM
                  (
                    RTRIM
                    (
                      COALESCE(d.DQ_Status, '')
                    )
                  )
                ) = 'failed'
                  THEN 1
                ELSE 0
              END
            ) AS failed_count,

            SUM
            (
              CASE
                WHEN LOWER
                (
                  LTRIM
                  (
                    RTRIM
                    (
                      COALESCE(d.DQ_Status, '')
                    )
                  )
                ) = 'approved'
                  THEN 1
                ELSE 0
              END
            ) AS approved_count,

            COALESCE
            (
              SUM
              (
                TRY_CAST
                (
                  d.Purchase_Dollars_Calc
                    AS DECIMAL(19, 2)
                )
              ),
              0
            ) AS total_purchase,

            COALESCE
            (
              SUM
              (
                TRY_CAST
                (
                  d.CAF_Dollars AS DECIMAL(19, 2)
                )
              ),
              0
            ) AS total_caf,

            CAST(
              'approved' AS NVARCHAR(20)
            ) AS report_status

          FROM dbo.Report_Number rn

          LEFT JOIN dbo.Ref_Supplier s
            ON s.BP_Code = rn.BP_Code

          LEFT JOIN dbo.Cur_Invoice_Header h
            ON h.Report_Number = rn.Report_Number

          LEFT JOIN dbo.Cur_Invoice_Detail d
            ON d.Report_Number = rn.Report_Number

          OUTER APPLY
          (
            SELECT
              STRING_AGG
              (
                CAST(
                  period_rows.Period AS NVARCHAR(50)
                ),
                ', '
              ) AS selected_periods

            FROM
            (
              SELECT DISTINCT
                rp.Period

              FROM dbo.Report_Period rp

              WHERE
                rp.Report_Number = rn.Report_Number

                AND rp.Period IS NOT NULL

                AND LTRIM
                (
                  RTRIM
                  (
                    CAST(
                      rp.Period AS NVARCHAR(50)
                    )
                  )
                ) <> ''
            ) period_rows
          ) period_data

          ${whereClause}

          GROUP BY
            rn.Report_Number,
            rn.Related_Report_Number,
            rn.Report_Type,
            rn.FileName,
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

          HAVING
            LOWER
            (
              LTRIM
              (
                RTRIM
                (
                  COALESCE
                  (
                    NULLIF(h.Report_Status, ''),
                    NULLIF(rn.Status, ''),
                    ''
                  )
                )
              )
            ) = 'approved'

            AND COUNT(d.Cur_Detail_ID) > 0

            AND SUM
            (
              CASE
                WHEN LOWER
                (
                  LTRIM
                  (
                    RTRIM
                    (
                      COALESCE(d.DQ_Status, '')
                    )
                  )
                ) = 'approved'
                  THEN 1
                ELSE 0
              END
            ) = COUNT(d.Cur_Detail_ID)
        )

        SELECT
          report_number,
          related_report_number,
          report_type,
          file_name,
          period,
          supplier_name,
          bp_code,
          contract_id,
          uploaded_by_display,
          uploaded_at_utc,
          report_status,
          passed_count,
          failed_count,
          approved_count,
          total_purchase,
          total_caf

        FROM base

        ORDER BY ${sortField} ${sortOrder};
      `;

      const { rows } = await query(sql, values);

      // ================================================================
      // CSV COLUMNS
      // ================================================================

      const headers = [
        "Report #",
        "Linked Report #",
        "Type",
        "File",
        "Period(s)",
        "Supplier Name",
        "Supplier Code",
        "Contract",
        "Uploaded By",
        "Uploaded At",
        "Status",
        "Passed",
        "Failed",
        "Approved",
        "Total Purchase $",
        "Total CAF $",
      ];

      const csvRows = [];

      let grandPurchaseTotal = 0;
      let grandCafTotal = 0;

      for (const report of rows || []) {
        const purchaseValue = Number(report.total_purchase || 0);

        const cafValue = Number(report.total_caf || 0);

        grandPurchaseTotal += Number.isFinite(purchaseValue)
          ? purchaseValue
          : 0;

        grandCafTotal += Number.isFinite(cafValue) ? cafValue : 0;

        csvRows.push([
          report.report_number,
          report.related_report_number,
          report.report_type,
          report.file_name,
          report.period,

          report.supplier_name,
          report.bp_code,
          report.contract_id,

          report.uploaded_by_display,

          report.uploaded_at_utc
            ? new Date(report.uploaded_at_utc).toLocaleString("en-US")
            : "",

          report.report_status,

          Number(report.passed_count || 0),
          Number(report.failed_count || 0),
          Number(report.approved_count || 0),

          formatCsvNumber(purchaseValue),
          formatCsvNumber(cafValue),
        ]);
      }

      // ================================================================
      // TOTAL ROW
      // ================================================================

      csvRows.push([
        "TOTAL",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        formatCsvNumber(grandPurchaseTotal),
        formatCsvNumber(grandCafTotal),
      ]);

      const csv = [
        headers.map(escapeCsv).join(","),

        ...csvRows.map((row) => row.map(escapeCsv).join(",")),
      ].join("\n");

      const fileTimestamp = Date.now();

      res.setHeader("Content-Type", "text/csv; charset=utf-8");

      res.setHeader(
        "Content-Disposition",
        `attachment; filename=ssp_reports_summary_${fileTimestamp}.csv`,
      );

      return res.status(200).send(`\uFEFF${csv}`);
    } catch (error) {
      console.error("❌ SSP Summary CSV export error:", error);

      return res.status(500).json({
        success: false,
        error: "Failed to export SSP summary CSV",
        code: "SSP_SUMMARY_CSV_EXPORT_FAILED",
      });
    }
  },
);

/* ======================================================================
   DOWNLOAD VRF DETAIL CSV

   GET /api/ssp/reports/:report_number/download

   Behavior:
   - Downloads all detail records for one report.
   - Preserves the existing database-column export.
   - Appends a final TOTAL row.
   - Totals Purchase_Dollars_Calc and CAF_Dollars.
====================================================================== */

router.get(
  "/ssp/reports/:report_number/download",
  requireInternalAuth,
  async (req, res) => {
    try {
      const reportNumber = Number(req.params.report_number);

      if (!Number.isInteger(reportNumber) || reportNumber <= 0) {
        return res.status(400).json({
          error: "Invalid report number",
          code: "INVALID_REPORT_NUMBER",
        });
      }

      const { rows } = await query(
        `
        SELECT *
        FROM dbo.Cur_Invoice_Detail
        WHERE Report_Number = @p1
        ORDER BY Cur_Detail_ID;
        `,
        [reportNumber],
      );

      if (!rows.length) {
        return res.status(404).json({
          error: "Report not found",
          code: "REPORT_NOT_FOUND",
        });
      }

      // ================================================================
      // HEADERS
      // ================================================================

      const columnNames = Object.keys(rows[0]);

      const normalizedColumnMap = new Map(
        columnNames.map((columnName) => [columnName.toLowerCase(), columnName]),
      );

      const purchaseColumn =
        normalizedColumnMap.get("purchase_dollars_calc") ||
        normalizedColumnMap.get("purchase_dollars") ||
        null;

      const cafDollarsColumn = normalizedColumnMap.get("caf_dollars") || null;

      // ================================================================
      // DETAIL ROWS AND TOTALS
      // ================================================================

      let purchaseTotal = 0;
      let cafTotal = 0;

      const csvRows = rows.map((row) => {
        const purchaseValue = purchaseColumn
          ? Number(row[purchaseColumn] || 0)
          : 0;

        const cafValue = cafDollarsColumn
          ? Number(row[cafDollarsColumn] || 0)
          : 0;

        purchaseTotal += Number.isFinite(purchaseValue) ? purchaseValue : 0;

        cafTotal += Number.isFinite(cafValue) ? cafValue : 0;

        return columnNames.map((columnName) => row[columnName]);
      });

      // ================================================================
      // TOTAL ROW
      // ================================================================

      const totalRow = columnNames.map(() => "");

      /*
       * Put TOTAL in the first exported column.
       */
      if (totalRow.length > 0) {
        totalRow[0] = "TOTAL";
      }

      if (purchaseColumn) {
        const purchaseColumnIndex = columnNames.indexOf(purchaseColumn);

        if (purchaseColumnIndex >= 0) {
          totalRow[purchaseColumnIndex] = formatCsvNumber(purchaseTotal);
        }
      }

      if (cafDollarsColumn) {
        const cafColumnIndex = columnNames.indexOf(cafDollarsColumn);

        if (cafColumnIndex >= 0) {
          totalRow[cafColumnIndex] = formatCsvNumber(cafTotal);
        }
      }

      csvRows.push(totalRow);

      // ================================================================
      // CREATE CSV
      // ================================================================

      const csv = [
        columnNames.map(escapeCsv).join(","),

        ...csvRows.map((row) => row.map(escapeCsv).join(",")),
      ].join("\n");

      res.setHeader("Content-Type", "text/csv; charset=utf-8");

      res.setHeader(
        "Content-Disposition",
        `attachment; filename=vrf_report_${reportNumber}.csv`,
      );

      /*
       * UTF-8 BOM helps Excel display special characters correctly.
       */
      return res.status(200).send(`\uFEFF${csv}`);
    } catch (error) {
      console.error("❌ VRF CSV error:", error);

      return res.status(500).json({
        error: "Failed to download report CSV",
        code: "VRF_CSV_DOWNLOAD_FAILED",
      });
    }
  },
);

export default router;
