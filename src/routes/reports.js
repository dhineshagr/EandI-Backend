import { Router } from "express";
import { query } from "../db.js";
import { requireAuth } from "../middleware/auth.js";

const router = Router();

/* ======================================================================
   Helpers
====================================================================== */
const asInt = (v, d = 0) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
};

/* ======================================================================
   REGISTER REPORT (Metadata only)
====================================================================== */
/* ======================================================================
   REGISTER REPORT (Metadata only)
   - Supports legacy single period
   - Supports multiple periods
   - Stores a summary value in Report_Number.Period
   - Stores one row per period in Report_Period
====================================================================== */
router.post("/reports/register", requireAuth, async (req, res, next) => {
  try {
    const {
      filename,
      report_type = "Members",
      note = "",
      period = null,
      periods = [],
      bp_code = null,
      contract_id = null,
      related_report_number = null,
    } = req.body || {};

    if (!filename) {
      return res.status(400).json({
        error: "filename is required",
      });
    }

    /*
     * Normalize periods.
     *
     * New request:
     * periods: ["2026-04", "2026-05"]
     *
     * Legacy request:
     * period: "2026-04"
     */
    const normalizedPeriods = Array.from(
      new Set(
        [
          ...(Array.isArray(periods) ? periods : []),
          ...(period ? [period] : []),
        ]
          .map((value) => String(value || "").trim())
          .filter(Boolean),
      ),
    );

    /*
     * Keep Report_Number.Period for backward compatibility.
     * For multiple periods, store a comma-separated summary.
     */
    const periodSummary =
      normalizedPeriods.length > 0 ? normalizedPeriods.join(", ") : null;

    const uploaded_by = req.user?.email || req.user?.username || "unknown@user";

    const uploaded_by_name =
      req.user?.display_name ||
      req.user?.name ||
      req.user?.username ||
      (req.user?.email ? req.user.email.split("@")[0] : "Unknown");

    const uploaded_by_type = req.user?.user_type || "internal";

    const reportInsertSql = `
      INSERT INTO dbo.Report_Number
      (
        FileName,
        Report_Type,
        Uploaded_By,
        Uploaded_By_Name,
        Uploaded_By_Type,
        Period,
        BP_Code,
        Contract_ID,
        Related_Report_Number,
        Uploaded_At_UTC,
        Status,
        Note,
        Created_At_UTC,
        Updated_At_UTC
      )
      OUTPUT
        INSERTED.Report_Number AS report_number,
        INSERTED.FileName AS filename,
        INSERTED.Report_Type AS report_type,
        INSERTED.Period AS period,
        INSERTED.BP_Code AS bp_code,
        INSERTED.Contract_ID AS contract_id,
        INSERTED.Related_Report_Number AS related_report_number,
        INSERTED.Uploaded_By AS uploaded_by,
        INSERTED.Uploaded_By_Name AS uploaded_by_name,
        INSERTED.Uploaded_By_Type AS uploaded_by_type,
        INSERTED.Uploaded_At_UTC AS uploaded_at_utc,
        INSERTED.Status AS status,
        INSERTED.Note AS note
      VALUES
      (
        @p1,
        @p2,
        @p3,
        @p4,
        @p5,
        @p6,
        @p7,
        @p8,
        @p9,
        GETUTCDATE(),
        'new',
        @p10,
        GETUTCDATE(),
        GETUTCDATE()
      );
    `;

    const { rows: reportRows } = await query(reportInsertSql, [
      filename,
      report_type,
      uploaded_by,
      uploaded_by_name,
      uploaded_by_type,
      periodSummary,
      bp_code || null,
      contract_id || null,
      related_report_number || null,
      note || "",
    ]);

    const report = reportRows?.[0];
    const reportNumber = report?.report_number;

    if (!reportNumber) {
      return res.status(500).json({
        error: "Failed to register report",
      });
    }

    /*
     * Insert one row per selected accounting period.
     */
    for (const selectedPeriod of normalizedPeriods) {
      await query(
        `
        INSERT INTO dbo.Report_Period
        (
          Report_Number,
          Period,
          Created_At_UTC,
          Updated_At_UTC
        )
        VALUES
        (
          @p1,
          @p2,
          GETUTCDATE(),
          GETUTCDATE()
        );
        `,
        [reportNumber, selectedPeriod],
      );
    }

    /*
     * Audit logging should not fail the report registration.
     */
    try {
      await query(
        `
        INSERT INTO dbo.Users_Audit_Log
        (
          User_Email,
          Action,
          Context_JSON,
          Created_At_UTC
        )
        VALUES
        (
          @p1,
          'register_report',
          @p2,
          GETUTCDATE()
        );
        `,
        [
          uploaded_by,
          JSON.stringify({
            report_number: reportNumber,
            filename,
            report_type,
            note,
            period: periodSummary,
            periods: normalizedPeriods,
            bp_code: bp_code || null,
            contract_id: contract_id || null,
            related_report_number: related_report_number || null,
          }),
        ],
      );
    } catch (auditErr) {
      console.warn("Register report audit log skipped:", auditErr.message);
    }

    res.json({
      ok: true,
      report: {
        ...report,
        period: periodSummary,
        periods: normalizedPeriods,
      },
    });
  } catch (err) {
    console.error("❌ POST /reports/register error:", err);
    next(err);
  }
});

/* ======================================================================
   LIST REPORTS (Dashboard)
====================================================================== */
/* ======================================================================
   LIST REPORTS (Dashboard)
   - Supports legacy single period
   - Supports multiple periods from Report_Period
   - Returns both period and periods[]
   - Prevents Report_Period from multiplying detail-row totals
====================================================================== */
router.get("/reports/list", requireAuth, async (_req, res, next) => {
  try {
    const sql = `
      SELECT
        r.Report_Number AS report_number,
        r.FileName AS filename,
        r.Report_Type AS report_type,

        COALESCE(
          NULLIF(period_data.selected_periods, ''),
          NULLIF(r.Period, '')
        ) AS period,

        r.BP_Code AS bp_code,
        r.Contract_ID AS contract_id,
        r.Related_Report_Number AS related_report_number,

        r.Uploaded_By AS uploaded_by,
        r.Uploaded_At_UTC AS uploaded_at_utc,

        COALESCE(
          NULLIF(r.Uploaded_By_Name, ''),
          NULLIF(r.Uploaded_By, ''),
          'System'
        ) AS uploaded_by_display,

        r.Uploaded_By_Name AS uploaded_by_name,
        r.Uploaded_By_Type AS uploaded_by_type,

        COUNT(d.Cur_Detail_ID) AS total_rows,

        SUM(
          CASE
            WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'passed'
              THEN 1
            ELSE 0
          END
        ) AS passed_count,

        SUM(
          CASE
            WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'failed'
              THEN 1
            ELSE 0
          END
        ) AS failed_count,

        SUM(
          CASE
            WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'approved'
              THEN 1
            ELSE 0
          END
        ) AS approved_count,

        SUM(
          CASE
            WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'validated'
              THEN 1
            ELSE 0
          END
        ) AS validated_count,

        CASE
          /*
           * Zero Sales reports do not have detail rows.
           */
          WHEN UPPER(LTRIM(RTRIM(r.FileName))) = 'ZERO_SALES'
            OR UPPER(LTRIM(RTRIM(r.FileName))) LIKE 'ZERO_SALES%'
            THEN 'submitted'

          /*
           * Prefer explicit approved status from Report_Number.
           */
          WHEN LOWER(COALESCE(NULLIF(r.Status, ''), '')) = 'approved'
            THEN 'approved'

          /*
           * Any failed row means the report failed.
           */
          WHEN SUM(
            CASE
              WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'failed'
                THEN 1
              ELSE 0
            END
          ) > 0
            THEN 'failed'

          /*
           * All detail rows approved.
           */
          WHEN COUNT(d.Cur_Detail_ID) > 0
            AND SUM(
              CASE
                WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'approved'
                  THEN 1
                ELSE 0
              END
            ) = COUNT(d.Cur_Detail_ID)
            THEN 'approved'

          /*
           * All detail rows passed.
           */
          WHEN COUNT(d.Cur_Detail_ID) > 0
            AND SUM(
              CASE
                WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'passed'
                  THEN 1
                ELSE 0
              END
            ) = COUNT(d.Cur_Detail_ID)
            THEN 'passed'

          /*
           * At least one validated row.
           */
          WHEN SUM(
            CASE
              WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'validated'
                THEN 1
              ELSE 0
            END
          ) > 0
            THEN 'validated'

          /*
           * Preserve current Report_Number status when available.
           */
          WHEN LOWER(COALESCE(NULLIF(r.Status, ''), '')) IN
            ('new', 'staged', 'submitted', 'pending', 'processing')
            THEN LOWER(r.Status)

          /*
           * No detail rows yet.
           */
          ELSE 'pending'
        END AS status

      FROM dbo.Report_Number r

      LEFT JOIN dbo.Cur_Invoice_Detail d
        ON d.Report_Number = r.Report_Number

      /*
       * Aggregate periods before joining to detail records.
       * This prevents duplicate detail counts and dollar totals.
       */
      OUTER APPLY (
        SELECT
          STRING_AGG(
            CAST(period_rows.Period AS NVARCHAR(50)),
            ', '
          ) AS selected_periods
        FROM (
          SELECT DISTINCT rp.Period
          FROM dbo.Report_Period rp
          WHERE rp.Report_Number = r.Report_Number
            AND rp.Period IS NOT NULL
            AND LTRIM(RTRIM(CAST(rp.Period AS NVARCHAR(50)))) <> ''
        ) period_rows
      ) period_data

      GROUP BY
        r.Report_Number,
        r.FileName,
        r.Report_Type,
        r.Period,
        period_data.selected_periods,
        r.BP_Code,
        r.Contract_ID,
        r.Related_Report_Number,
        r.Uploaded_By,
        r.Uploaded_By_Name,
        r.Uploaded_By_Type,
        r.Uploaded_At_UTC,
        r.Status

      ORDER BY r.Uploaded_At_UTC DESC;
    `;

    const { rows } = await query(sql);

    /*
     * Return both:
     * period  = "2026-04, 2026-05"
     * periods = ["2026-04", "2026-05"]
     */
    const reports = rows.map((report) => {
      const periods = String(report.period || "")
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);

      return {
        ...report,
        periods,
      };
    });

    res.json({
      reports,
    });
  } catch (err) {
    console.error("❌ GET /reports/list error:", err);
    next(err);
  }
});

/* ======================================================================
   REPORT SUMMARY
====================================================================== */
/* ======================================================================
   REPORT SUMMARY
   - Returns report header metadata
   - Returns DQ counts
   - Supports multiple periods
   - Supports legacy Report_Number.Period fallback
   - Supports Zero Sales reports with no detail rows
====================================================================== */
router.get(
  "/reports/:reportNumber/summary",
  requireAuth,
  async (req, res, next) => {
    try {
      const rn = asInt(req.params.reportNumber);

      if (!rn) {
        return res.status(400).json({
          error: "Invalid report number",
        });
      }

      const sql = `
        SELECT
          r.Report_Number AS report_number,
          r.FileName AS filename,
          r.Report_Type AS report_type,

          COALESCE(
            NULLIF(period_data.selected_periods, ''),
            NULLIF(r.Period, '')
          ) AS period,

          r.BP_Code AS bp_code,
          r.Contract_ID AS contract_id,
          r.Related_Report_Number AS related_report_number,

          r.Uploaded_By AS uploaded_by,
          r.Uploaded_By_Name AS uploaded_by_name,
          r.Uploaded_By_Type AS uploaded_by_type,
          r.Uploaded_At_UTC AS uploaded_at_utc,

          COALESCE(
            NULLIF(r.Uploaded_By_Name, ''),
            NULLIF(r.Uploaded_By, ''),
            'System'
          ) AS uploaded_by_display,

          COUNT(d.Cur_Detail_ID) AS total_rows,

          SUM(
            CASE
              WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'passed'
                THEN 1
              ELSE 0
            END
          ) AS passed_count,

          SUM(
            CASE
              WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'failed'
                THEN 1
              ELSE 0
            END
          ) AS failed_count,

          SUM(
            CASE
              WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'approved'
                THEN 1
              ELSE 0
            END
          ) AS approved_count,

          SUM(
            CASE
              WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'validated'
                THEN 1
              ELSE 0
            END
          ) AS validated_count,

          CASE
            /*
             * Zero Sales reports do not contain detail rows.
             */
            WHEN UPPER(LTRIM(RTRIM(r.FileName))) = 'ZERO_SALES'
              OR UPPER(LTRIM(RTRIM(r.FileName))) LIKE 'ZERO_SALES%'
              THEN 'submitted'

            /*
             * Prefer the explicit approved header status.
             */
            WHEN LOWER(COALESCE(NULLIF(r.Status, ''), '')) = 'approved'
              THEN 'approved'

            /*
             * Any failed detail row means the report failed.
             */
            WHEN SUM(
              CASE
                WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'failed'
                  THEN 1
                ELSE 0
              END
            ) > 0
              THEN 'failed'

            /*
             * Every detail row approved.
             */
            WHEN COUNT(d.Cur_Detail_ID) > 0
              AND SUM(
                CASE
                  WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'approved'
                    THEN 1
                  ELSE 0
                END
              ) = COUNT(d.Cur_Detail_ID)
              THEN 'approved'

            /*
             * Every detail row passed.
             */
            WHEN COUNT(d.Cur_Detail_ID) > 0
              AND SUM(
                CASE
                  WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'passed'
                    THEN 1
                  ELSE 0
                END
              ) = COUNT(d.Cur_Detail_ID)
              THEN 'passed'

            /*
             * At least one detail row validated.
             */
            WHEN SUM(
              CASE
                WHEN LOWER(COALESCE(d.DQ_Status, '')) = 'validated'
                  THEN 1
                ELSE 0
              END
            ) > 0
              THEN 'validated'

            /*
             * Preserve an existing processing status.
             */
            WHEN LOWER(COALESCE(NULLIF(r.Status, ''), '')) IN
              ('new', 'staged', 'submitted', 'pending', 'processing')
              THEN LOWER(r.Status)

            ELSE 'pending'
          END AS report_status

        FROM dbo.Report_Number r

        LEFT JOIN dbo.Cur_Invoice_Detail d
          ON d.Report_Number = r.Report_Number

        OUTER APPLY (
          SELECT
            STRING_AGG(
              CAST(period_rows.Period AS NVARCHAR(50)),
              ', '
            ) AS selected_periods
          FROM (
            SELECT DISTINCT rp.Period
            FROM dbo.Report_Period rp
            WHERE rp.Report_Number = r.Report_Number
              AND rp.Period IS NOT NULL
              AND LTRIM(
                RTRIM(
                  CAST(rp.Period AS NVARCHAR(50))
                )
              ) <> ''
          ) period_rows
        ) period_data

        WHERE r.Report_Number = @p1

        GROUP BY
          r.Report_Number,
          r.FileName,
          r.Report_Type,
          r.Period,
          period_data.selected_periods,
          r.BP_Code,
          r.Contract_ID,
          r.Related_Report_Number,
          r.Uploaded_By,
          r.Uploaded_By_Name,
          r.Uploaded_By_Type,
          r.Uploaded_At_UTC,
          r.Status;
      `;

      const { rows } = await query(sql, [rn]);

      if (!rows.length) {
        return res.status(404).json({
          error: "Report not found",
        });
      }

      const row = rows[0];

      const periods = String(row.period || "")
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);

      const report = {
        report_number: row.report_number,
        filename: row.filename,
        report_type: row.report_type,
        period: row.period || null,
        periods,
        bp_code: row.bp_code || null,
        contract_id: row.contract_id || null,
        related_report_number: row.related_report_number || null,
        uploaded_by: row.uploaded_by || null,
        uploaded_by_name: row.uploaded_by_name || null,
        uploaded_by_type: row.uploaded_by_type || null,
        uploaded_by_display: row.uploaded_by_display || "System",
        uploaded_at_utc: row.uploaded_at_utc || null,
        report_status: row.report_status,
      };

      const counts = {
        total_rows: Number(row.total_rows || 0),
        passed_count: Number(row.passed_count || 0),
        failed_count: Number(row.failed_count || 0),
        approved_count: Number(row.approved_count || 0),
        validated_count: Number(row.validated_count || 0),
      };

      res.json({
        report,
        counts,
      });
    } catch (err) {
      console.error("❌ GET /reports/:reportNumber/summary error:", err);
      next(err);
    }
  },
);

/* ======================================================================
   DETAIL ROWS
====================================================================== */
router.get(
  "/reports/:reportNumber/rows",
  requireAuth,
  async (req, res, next) => {
    try {
      const rn = asInt(req.params.reportNumber);
      const { status, dq } = req.query;

      let sql = `
      SELECT *
      FROM cur_invoice_detail
      WHERE report_number=@p1
    `;

      const params = [rn];

      if (status) {
        sql += ` AND dq_status=@p${params.length + 1}`;
        params.push(status);
      }

      if (dq) {
        sql += ` AND LOWER(CAST(dq_messages AS NVARCHAR(MAX))) LIKE @p${
          params.length + 1
        }`;
        params.push(`%"${dq.toLowerCase()}"%`);
      }

      sql += `
      ORDER BY cur_detail_id;
    `;

      const { rows } = await query(sql, params);

      res.json({
        rows,
        count: rows.length,
      });
    } catch (err) {
      console.error("❌ GET rows error:", err);
      next(err);
    }
  },
);

/* ======================================================================
   UPDATE SINGLE FIELD + AUDIT
====================================================================== */
router.put(
  "/reports/:reportNumber/row/:curDetailId",
  requireAuth,
  async (req, res, next) => {
    try {
      const rn = asInt(req.params.reportNumber);
      const curDetailId = asInt(req.params.curDetailId);
      const { field_name, new_value, reason } = req.body || {};

      if (!field_name) {
        return res.status(400).json({ error: "field_name required" });
      }

      const { rows: cols } = await query(`
      SELECT column_name
      FROM INFORMATION_SCHEMA.COLUMNS
      WHERE table_name='cur_invoice_detail';
    `);

      const allowed = cols.map((c) => c.column_name);
      const readOnly = [
        "cur_detail_id",
        "report_number",
        "approved_by",
        "approved_at_utc",
        "created_at_utc",
        "updated_at_utc",
      ];

      if (!allowed.includes(field_name) || readOnly.includes(field_name)) {
        return res.status(400).json({ error: "Invalid or read-only field" });
      }

      const { rows: oldRows } = await query(
        `SELECT CAST(${field_name} AS NVARCHAR(MAX)) AS old_value
       FROM cur_invoice_detail
       WHERE cur_detail_id=@p1 AND report_number=@p2`,
        [curDetailId, rn],
      );

      if (!oldRows.length)
        return res.status(404).json({ error: "Row not found" });

      const { rows: updRows } = await query(
        `UPDATE cur_invoice_detail
       SET ${field_name}=@p1, updated_at_utc=GETUTCDATE()
       OUTPUT INSERTED.*
       WHERE cur_detail_id=@p2 AND report_number=@p3`,
        [new_value, curDetailId, rn],
      );

      await query(
        `INSERT INTO audit_log
       (report_number,row_key,field_name,old_value,new_value,changed_by,change_reason,changed_at_utc)
       VALUES (@p1,@p2,@p3,@p4,@p5,@p6,@p7,GETUTCDATE())`,
        [
          rn,
          curDetailId,
          field_name,
          oldRows[0].old_value,
          String(new_value ?? ""),
          req.user?.email || "internal",
          reason || "Manual correction",
        ],
      );

      res.json({ ok: true, row: updRows[0] });
    } catch (err) {
      console.error("❌ UPDATE row error:", err);
      next(err);
    }
  },
);

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * BULK APPROVE (header + details)
 * ─────────────────────────────────────────────────────────────────────────────
 */
router.put(
  "/reports/:reportNumber/approve",
  requireAuth,
  async (req, res, next) => {
    try {
      const rn = asInt(req.params.reportNumber);
      const approver = req.user?.email || "internal";

      const detailUpd = await query(
        `UPDATE cur_invoice_detail
         SET dq_status='approved',
             approved_by=@p1,
             approved_at_utc=GETUTCDATE(),
             updated_at_utc=GETUTCDATE()
         OUTPUT INSERTED.cur_detail_id, INSERTED.dq_status
         WHERE report_number=@p2
           AND dq_status IN ('passed','failed','validated','new','staged');`,
        [approver, rn],
      );

      for (const row of detailUpd.rows) {
        await query(
          `INSERT INTO audit_log
           (report_number, row_key, field_name, old_value, new_value,
            changed_by, change_reason, changed_at_utc)
           VALUES (@p1,@p2,'dq_status',@p3,'approved',@p4,'bulk approve',GETUTCDATE());`,
          [rn, row.cur_detail_id, row.dq_status, approver],
        );
      }

      await query(
        `UPDATE cur_invoice_header
         SET report_status='approved',
             approved_by=@p1,
             approved_at_utc=GETUTCDATE(),
             updated_at_utc=GETUTCDATE()
         WHERE report_number=@p2;`,
        [approver, rn],
      );

      await query(
        `UPDATE report_number
         SET status='approved',
             updated_at_utc=GETUTCDATE()
         WHERE report_number=@p1;`,
        [rn],
      );

      try {
        await query(
          `INSERT INTO users_audit_log (user_email, action, context_json, created_at_utc)
           VALUES (@p1,'bulk_approve',@p2,GETUTCDATE());`,
          [approver, JSON.stringify({ report_number: rn })],
        );
      } catch (e) {
        console.warn("users_audit_log skipped:", e.message);
      }

      res.json({
        ok: true,
        approved_rows: detailUpd.rows.length,
        message: `${detailUpd.rows.length} rows approved by ${approver}`,
      });
    } catch (err) {
      console.error("❌ PUT /reports/:reportNumber/approve error:", err);
      next(err);
    }
  },
);

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * APPROVE A SINGLE ROW
 * ─────────────────────────────────────────────────────────────────────────────
 */
router.put(
  "/reports/:reportNumber/row/:curDetailId/approve",
  requireAuth,
  async (req, res, next) => {
    try {
      const rn = asInt(req.params.reportNumber);
      const curDetailId = asInt(req.params.curDetailId);
      const approver = String(req.user?.email || "internal");

      const { rows: oldRows } = await query(
        `SELECT dq_status
         FROM cur_invoice_detail
         WHERE report_number=@p1 AND cur_detail_id=@p2;`,
        [rn, curDetailId],
      );
      if (!oldRows.length)
        return res.status(404).json({ error: "Row not found" });

      const oldStatus = oldRows[0].dq_status;

      const { rows: updRows } = await query(
        `UPDATE cur_invoice_detail
         SET dq_status='approved',
             approved_by=@p3,
             approved_at_utc=GETUTCDATE(),
             updated_at_utc=GETUTCDATE()
         OUTPUT INSERTED.cur_detail_id, INSERTED.dq_status, INSERTED.approved_by, INSERTED.approved_at_utc
         WHERE report_number=@p1 AND cur_detail_id=@p2;`,
        [rn, curDetailId, approver],
      );

      await query(
        `INSERT INTO audit_log
         (report_number, row_key, field_name, old_value, new_value,
          changed_by, change_reason, changed_at_utc)
         VALUES (@p1,@p2,'dq_status',@p3,'approved',@p4,'single approve',GETUTCDATE());`,
        [rn, curDetailId, oldStatus, approver],
      );

      res.json({ ok: true, row: updRows[0] });
    } catch (err) {
      console.error(
        "❌ PUT /reports/:reportNumber/row/:curDetailId/approve error:",
        err,
      );
      next(err);
    }
  },
);

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * AUDIT LOG (filtering, pagination)
 * ─────────────────────────────────────────────────────────────────────────────
 */
router.get("/:reportNumber/audit-log", requireAuth, async (req, res, next) => {
  try {
    const rn = asInt(req.params.reportNumber);
    const {
      action,
      changed_by,
      start_date,
      end_date,
      limit = 50,
      offset = 0,
      search,
      sort = "changed_at_utc",
      order = "desc",
    } = req.query;

    const allowedSort = ["changed_at_utc", "changed_by", "field_name"];
    const sortCol = allowedSort.includes(sort) ? sort : "changed_at_utc";
    const sortOrder = String(order).toLowerCase() === "asc" ? "ASC" : "DESC";

    let sql = `
      SELECT audit_id, report_number, row_key, field_name, old_value, new_value,
             changed_by, change_reason, changed_at_utc
      FROM audit_log
      WHERE report_number=@p1
    `;
    const params = [rn];

    if (action) {
      sql += ` AND change_reason=@p${params.length + 1}`;
      params.push(action);
    }
    if (changed_by) {
      sql += ` AND LOWER(changed_by) LIKE LOWER(@p${params.length + 1})`;
      params.push(`%${changed_by}%`);
    }
    if (search) {
      const p = `%${search}%`;
      sql += ` AND (LOWER(field_name) LIKE LOWER(@p${params.length + 1})
                    OR LOWER(old_value) LIKE LOWER(@p${params.length + 1})
                    OR LOWER(new_value) LIKE LOWER(@p${params.length + 1}))`;
      params.push(p);
    }
    if (start_date) {
      sql += ` AND changed_at_utc >= @p${params.length + 1}`;
      params.push(start_date);
    }
    if (end_date) {
      sql += ` AND changed_at_utc <= @p${params.length + 1}`;
      params.push(end_date);
    }

    sql += ` ORDER BY ${sortCol} ${sortOrder}
             OFFSET @p${params.length + 1} ROWS FETCH NEXT @p${
               params.length + 2
             } ROWS ONLY;`;
    params.push(offset, limit);

    const { rows } = await query(sql, params);
    res.json({ logs: rows });
  } catch (err) {
    console.error("❌ GET /:reportNumber/audit-log error:", err);
    next(err);
  }
});

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * BACKWARD-COMPATIBLE AUDIT LOG ROUTE
 * ─────────────────────────────────────────────────────────────────────────────
 */
router.get(
  "/reports/:reportNumber/audit-log",
  requireAuth,
  async (req, res, next) => {
    try {
      const rn = asInt(req.params.reportNumber);
      const {
        search = "",
        sort = "changed_at_utc",
        order = "desc",
        limit = 50,
        offset = 0,
      } = req.query;

      const allowedSort = ["changed_at_utc", "changed_by", "field_name"];
      const sortCol = allowedSort.includes(sort) ? sort : "changed_at_utc";
      const sortOrder = order.toLowerCase() === "asc" ? "ASC" : "DESC";

      let sql = `
        SELECT audit_id, report_number, row_key, field_name, old_value, new_value,
               changed_by, change_reason, changed_at_utc
        FROM audit_log
        WHERE report_number=@p1
      `;
      const params = [rn];

      if (search) {
        const p = `%${search}%`;
        sql += ` AND (LOWER(field_name) LIKE LOWER(@p${params.length + 1})
                     OR LOWER(old_value) LIKE LOWER(@p${params.length + 1})
                     OR LOWER(new_value) LIKE LOWER(@p${params.length + 1})
                     OR LOWER(changed_by) LIKE LOWER(@p${params.length + 1})
                     OR LOWER(change_reason) LIKE LOWER(@p${
                       params.length + 1
                     }))`;
        params.push(p);
      }

      sql += ` ORDER BY ${sortCol} ${sortOrder}
               OFFSET @p${params.length + 1} ROWS FETCH NEXT @p${
                 params.length + 2
               } ROWS ONLY;`;
      params.push(offset, limit);

      const { rows } = await query(sql, params);
      res.json({ logs: rows });
    } catch (err) {
      console.error("❌ GET /reports/:reportNumber/audit-log error:", err);
      res.status(500).json({ error: "Failed to fetch report audit log" });
    }
  },
);

/* ======================================================================
   MANUAL CREATE REPORT
   - Supports Accrual and Return
   - Supports legacy period
   - Supports multiple periods
   - Stores summary in Report_Number.Period
   - Stores one row per period in Report_Period
   - Stages detail rows for Informatica processing
====================================================================== */
router.post("/reports/manual-create", requireAuth, async (req, res, next) => {
  try {
    const {
      report_type,
      period = null,
      periods = [],
      bp_code = null,
      contract_id = null,
      related_report_number = null,
      note = "",
      rows = [],
      validation_warnings = [],
      validation_error_details = "",
    } = req.body || {};

    const allowedTypes = ["Accrual", "Return"];

    if (!allowedTypes.includes(report_type)) {
      return res.status(400).json({
        error: "report_type must be Accrual or Return",
      });
    }

    /*
     * Support both:
     *
     * Legacy:
     * period: "2026-04"
     *
     * New:
     * periods: ["2026-04", "2026-05"]
     */
    const normalizedPeriods = Array.from(
      new Set(
        [
          ...(Array.isArray(periods) ? periods : []),
          ...(period ? [period] : []),
        ]
          .map((value) => String(value || "").trim())
          .filter(Boolean),
      ),
    );

    if (normalizedPeriods.length === 0) {
      return res.status(400).json({
        error: "At least one period is required",
      });
    }

    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(400).json({
        error: "At least one detail row is required",
      });
    }

    /*
     * Keep Report_Number.Period populated for backward compatibility.
     */
    const periodSummary = normalizedPeriods.join(", ");

    const uploaded_by = req.user?.email || req.user?.username || "unknown@user";

    const uploaded_by_name =
      req.user?.display_name ||
      req.user?.name ||
      req.user?.username ||
      (req.user?.email ? req.user.email.split("@")[0] : "Unknown");

    const uploaded_by_type = req.user?.user_type || "internal";

    /*
     * BP users must use their assigned BP code.
     * Internal users may use the submitted BP code.
     */
    const finalBpCode =
      req.user?.user_type === "bp"
        ? req.user?.bp_code || bp_code || null
        : bp_code || null;

    const manualFileName =
      report_type === "Accrual" ? "MANUAL_ACCRUAL" : "MANUAL_RETURN";

    /* ==================================================================
       CREATE REPORT HEADER
    ================================================================== */
    const reportInsertSql = `
      INSERT INTO dbo.Report_Number
      (
        FileName,
        Report_Type,
        Uploaded_By,
        Uploaded_By_Name,
        Uploaded_By_Type,
        Period,
        BP_Code,
        Contract_ID,
        Related_Report_Number,
        Uploaded_At_UTC,
        Status,
        Note,
        Created_At_UTC,
        Updated_At_UTC
      )
      OUTPUT
        INSERTED.Report_Number AS report_number,
        INSERTED.Report_Type AS report_type,
        INSERTED.FileName AS filename,
        INSERTED.Period AS period,
        INSERTED.BP_Code AS bp_code,
        INSERTED.Contract_ID AS contract_id,
        INSERTED.Related_Report_Number AS related_report_number,
        INSERTED.Uploaded_By AS uploaded_by,
        INSERTED.Uploaded_By_Name AS uploaded_by_name,
        INSERTED.Uploaded_By_Type AS uploaded_by_type,
        INSERTED.Uploaded_At_UTC AS uploaded_at_utc,
        INSERTED.Status AS status
      VALUES
      (
        @p1,
        @p2,
        @p3,
        @p4,
        @p5,
        @p6,
        @p7,
        @p8,
        @p9,
        GETUTCDATE(),
        'submitted',
        @p10,
        GETUTCDATE(),
        GETUTCDATE()
      );
    `;

    const { rows: reportRows } = await query(reportInsertSql, [
      manualFileName,
      report_type,
      uploaded_by,
      uploaded_by_name,
      uploaded_by_type,
      periodSummary,
      finalBpCode,
      contract_id || null,
      related_report_number || null,
      note || "",
    ]);

    const report = reportRows?.[0];
    const reportNumber = report?.report_number ?? report?.Report_Number ?? null;

    if (!reportNumber) {
      return res.status(500).json({
        error: "Failed to create report header: missing report number",
      });
    }

    /* ==================================================================
       STORE SELECTED PERIODS
    ================================================================== */
    for (const selectedPeriod of normalizedPeriods) {
      await query(
        `
        INSERT INTO dbo.Report_Period
        (
          Report_Number,
          Period,
          Created_At_UTC,
          Updated_At_UTC
        )
        VALUES
        (
          @p1,
          @p2,
          GETUTCDATE(),
          GETUTCDATE()
        );
        `,
        [reportNumber, selectedPeriod],
      );
    }

    /* ==================================================================
       CREATE CURATED HEADER
    ================================================================== */
    await query(
      `
      INSERT INTO dbo.Cur_Invoice_Header
      (
        Report_Number,
        Report_Status,
        Uploaded_By,
        Uploaded_At_UTC,
        Created_At_UTC,
        Updated_At_UTC
      )
      VALUES
      (
        @p1,
        'submitted',
        @p2,
        GETUTCDATE(),
        GETUTCDATE(),
        GETUTCDATE()
      );
      `,
      [reportNumber, uploaded_by],
    );

    /* ==================================================================
       STAGE DETAIL ROWS
    ================================================================== */
    const stageSql = `
      INSERT INTO dbo.Stg_Invoice_Raw
      (
        Report_Number,
        Customer_ID,
        Member_Number,
        Member_Name,
        Member_Address,
        Member_City,
        Member_State,
        Member_Zip,
        PO,
        Invoice,
        Invoice_Date,
        Ship_To,
        Ship_To_Address,
        Ship_To_City,
        Ship_To_State,
        Ship_To_Zip,
        Item,
        Manufacturer,
        Manufacturer_Part,
        UM,
        [Desc],
        UNSPSC,
        Category,
        SubCategory,
        Retail_Price,
        Contract_Price,
        Qty,
        Purchase_Dollars,
        CAF,
        CAF_Dollars,
        Created_At_UTC
      )
      VALUES
      (
        @p1,
        @p2,
        @p3,
        @p4,
        @p5,
        @p6,
        @p7,
        @p8,
        @p9,
        @p10,
        @p11,
        @p12,
        @p13,
        @p14,
        @p15,
        @p16,
        @p17,
        @p18,
        @p19,
        @p20,
        @p21,
        @p22,
        @p23,
        @p24,
        @p25,
        @p26,
        @p27,
        @p28,
        @p29,
        @p30,
        GETUTCDATE()
      );
    `;

    for (const row of rows) {
      await query(stageSql, [
        reportNumber,
        row.customer_id || null,
        row.member_number || null,
        row.member_name || null,
        row.member_address || null,
        row.member_city || null,
        row.member_state || null,
        row.member_zip || null,
        row.po || null,
        row.invoice || null,
        row.invoice_date || null,
        row.ship_to || null,
        row.ship_to_address || null,
        row.ship_to_city || null,
        row.ship_to_state || null,
        row.ship_to_zip || null,
        row.item || null,
        row.manufacturer || null,
        row.manufacturer_part || null,
        row.um || null,
        row.desc || row.description || null,
        row.unspsc || null,
        row.category || null,
        row.subcategory || null,
        row.retail_price ?? null,
        row.contract_price ?? null,
        row.qty ?? null,
        row.purchase_dollars ?? row.purchase_dollars_calc ?? null,
        row.caf ?? null,
        row.caf_dollars ?? null,
      ]);
    }

    /* ==================================================================
       TRIGGER INFORMATICA / PROCESSING PIPELINE
    ================================================================== */
    let trigger_result = null;

    try {
      if (process.env.PIPELINE_TRIGGER_URL) {
        const triggerRes = await fetch(process.env.PIPELINE_TRIGGER_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            report_number: reportNumber,
            report_type,
            period: periodSummary,
            periods: normalizedPeriods,
            bp_code: finalBpCode,
            contract_id: contract_id || null,
            related_report_number: related_report_number || null,
            source: "manual_ui",
            uploaded_by,
          }),
        });

        trigger_result = {
          ok: triggerRes.ok,
          status: triggerRes.status,
        };
      }
    } catch (triggerErr) {
      trigger_result = {
        ok: false,
        error: triggerErr.message,
      };

      console.warn(
        "Manual report pipeline trigger failed:",
        triggerErr.message,
      );
    }

    /* ==================================================================
       AUDIT LOG
    ================================================================== */
    try {
      await query(
        `
        INSERT INTO dbo.Users_Audit_Log
        (
          User_Email,
          Action,
          Context_JSON,
          Created_At_UTC
        )
        VALUES
        (
          @p1,
          'manual_create_report',
          @p2,
          GETUTCDATE()
        );
        `,
        [
          uploaded_by,
          JSON.stringify({
            report_number: reportNumber,
            report_type,
            period: periodSummary,
            periods: normalizedPeriods,
            bp_code: finalBpCode,
            contract_id: contract_id || null,
            related_report_number: related_report_number || null,
            row_count: rows.length,
            validation_warnings,
            validation_error_details,
            trigger_result,
          }),
        ],
      );
    } catch (auditErr) {
      console.warn("Manual report audit log skipped:", auditErr.message);
    }

    /* ==================================================================
       RESPONSE
    ================================================================== */
    res.json({
      ok: true,
      report_number: reportNumber,
      report: {
        ...report,
        period: periodSummary,
        periods: normalizedPeriods,
      },
      row_count: rows.length,
      status: "submitted",
      trigger_result,
      message:
        "Manual report created and staged for validation. Informatica processing will determine final DQ status.",
    });
  } catch (err) {
    console.error("❌ POST /reports/manual-create error:", err);
    next(err);
  }
});

export default router;
