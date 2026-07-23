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

const nullIfEmpty = (value) => {
  if (value === undefined || value === null || String(value).trim() === "") {
    return null;
  }

  return value;
};

const nullableNumber = (value) => {
  if (value === undefined || value === null || value === "") {
    return null;
  }

  const numericValue = Number(value);

  return Number.isFinite(numericValue) ? numericValue : null;
};

const reverseAmount = (value) => {
  const numericValue = nullableNumber(value);

  return numericValue === null ? null : numericValue * -1;
};

const validateOpenPeriods = async (periods) => {
  const normalizedPeriods = Array.from(
    new Set(
      (Array.isArray(periods) ? periods : [])
        .map((value) => String(value || "").trim())
        .filter(Boolean),
    ),
  );

  if (normalizedPeriods.length === 0) {
    return;
  }

  const placeholders = normalizedPeriods
    .map((_, index) => `@p${index + 1}`)
    .join(", ");

  const { rows } = await query(
    `
    SELECT
      Period AS period,
      Is_Locked AS is_locked,
      Locked_By AS locked_by,
      Locked_At_UTC AS locked_at_utc
    FROM dbo.Accounting_Period
    WHERE Period IN (${placeholders});
    `,
    normalizedPeriods,
  );

  const configuredPeriodMap = new Map(
    rows.map((row) => [
      String(row.period || "").trim(),
      {
        isLocked: Boolean(row.is_locked),
        lockedBy: row.locked_by || null,
        lockedAtUtc: row.locked_at_utc || null,
      },
    ]),
  );

  /*
   * Block periods that are not configured.
   */
  const missingPeriods = normalizedPeriods.filter(
    (selectedPeriod) => !configuredPeriodMap.has(selectedPeriod),
  );

  if (missingPeriods.length > 0) {
    const error = new Error(
      `The following accounting period(s) are not configured: ${missingPeriods.join(
        ", ",
      )}.`,
    );

    error.statusCode = 400;
    error.code = "ACCOUNTING_PERIOD_NOT_CONFIGURED";
    error.periods = missingPeriods;

    throw error;
  }

  /*
   * Block configured periods that are locked.
   */
  const lockedPeriods = normalizedPeriods.filter(
    (selectedPeriod) =>
      configuredPeriodMap.get(selectedPeriod)?.isLocked === true,
  );

  if (lockedPeriods.length > 0) {
    const error = new Error(
      `The following accounting period(s) are closed: ${lockedPeriods.join(
        ", ",
      )}.`,
    );

    error.statusCode = 400;
    error.code = "ACCOUNTING_PERIOD_CLOSED";
    error.periods = lockedPeriods;

    throw error;
  }
};

// ============================================================
// ACCOUNTING PERIOD HELPERS
// ============================================================

/**
 * Accepts YYYY-MM only.
 *
 * Valid:
 *   2026-01
 *   2026-12
 *
 * Invalid:
 *   01-2026
 *   2026-1
 *   July 2026
 */
function normalizeAccountingPeriod(value) {
  const period = String(value || "").trim();

  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(period)) {
    return null;
  }

  return period;
}

/**
 * Returns the current logged-in user's best available identifier.
 *
 * Update these property names if your /me endpoint uses different fields.
 */
function getCurrentUserIdentifier(req) {
  return (
    req.user?.email ||
    req.user?.username ||
    req.user?.display_name ||
    req.session?.user?.email ||
    req.session?.user?.username ||
    req.session?.user?.display_name ||
    "Unknown User"
  );
}

/**
 * Checks whether the current user is an internal user.
 *
 * Business Partner users have user_type = "bp".
 */
function isInternalUser(req) {
  const userType = String(
    req.user?.user_type || req.session?.user?.user_type || "",
  )
    .trim()
    .toLowerCase();

  return userType !== "bp";
}

/**
 * Middleware used by the period-management write APIs.
 *
 * All internal users are allowed.
 */
function requireInternalAccountingPeriodAccess(req, res, next) {
  if (!req.user && !req.session?.user) {
    return res.status(401).json({
      success: false,
      code: "UNAUTHENTICATED",
      message: "Authentication is required.",
    });
  }

  if (!isInternalUser(req)) {
    return res.status(403).json({
      success: false,
      code: "INTERNAL_USER_REQUIRED",
      message: "Only internal users can manage accounting periods.",
    });
  }

  return next();
}
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
   ----------------------------------------------------------------------
   Supported report types:

   1. Report
      - User manually enters rows.
      - Linked report is not required.

   2. Adjustment
      - User manually enters rows.
      - Linked original report is required.

   3. Return
      - Linked approved Accrual report is required.
      - Manual rows are not required.
      - Approved processed rows are copied from Cur_Invoice_Detail.
      - Purchase_Dollars_Calc is reversed and inserted into
        Stg_Invoice_Raw.Purchase_Dollars.
      - CAF_Dollars is reversed.
      - CAF rate, quantity, and prices remain unchanged.
      - Supplier, Contract, and Periods are inherited from the Accrual.

   Processing:
      - Creates Report_Number with submitted status.
      - Creates Report_Period records.
      - Creates Cur_Invoice_Header.
      - Inserts detail rows into Stg_Invoice_Raw.
      - Existing scheduled IICS workflow processes submitted reports.
      - Backend does not directly trigger Informatica.
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

    /* ==================================================================
       VALIDATE REPORT TYPE
    ================================================================== */

    const allowedTypes = ["Report", "Adjustment", "Return"];

    if (!allowedTypes.includes(report_type)) {
      return res.status(400).json({
        error: "report_type must be Report, Adjustment, or Return",
      });
    }

    const isReport = report_type === "Report";
    const isAdjustment = report_type === "Adjustment";
    const isReturn = report_type === "Return";

    const requiresManualRows = isReport || isAdjustment;

    /* ==================================================================
       VALIDATE LINKED REPORT NUMBER
    ================================================================== */

    let linkedReportNumber = null;

    if (isAdjustment || isReturn) {
      linkedReportNumber = Number(related_report_number);

      if (!Number.isInteger(linkedReportNumber) || linkedReportNumber <= 0) {
        return res.status(400).json({
          error: isReturn
            ? "Linked Accrual Report # must be a positive integer"
            : "Linked Original Report # must be a positive integer",
        });
      }
    }

    /* ==================================================================
       VALIDATE MANUAL ROWS
    ================================================================== */

    if (requiresManualRows && (!Array.isArray(rows) || rows.length === 0)) {
      return res.status(400).json({
        error: `At least one detail row is required for a ${report_type}`,
      });
    }

    /* ==================================================================
       NORMALIZE SUBMITTED PERIODS

       Report and Adjustment use submitted periods.
       Return inherits periods from the linked Accrual.
    ================================================================== */

    const submittedPeriods = Array.from(
      new Set(
        [
          ...(Array.isArray(periods) ? periods : []),
          ...(period ? [period] : []),
        ]
          .map((value) => String(value || "").trim())
          .filter(Boolean),
      ),
    ).sort((left, right) => left.localeCompare(right));

    if (!isReturn && submittedPeriods.length === 0) {
      return res.status(400).json({
        error: "At least one accounting period is required",
      });
    }

    /* ==================================================================
       USER INFORMATION
    ================================================================== */

    const uploadedBy = req.user?.email || req.user?.username || "unknown@user";

    const uploadedByName =
      req.user?.display_name ||
      req.user?.name ||
      req.user?.username ||
      (req.user?.email ? req.user.email.split("@")[0] : "Unknown");

    const uploadedByType = req.user?.user_type || "internal";

    /*
     * BP users must use the supplier code assigned to their login.
     * Internal users can use the supplier code selected in the UI.
     */
    const submittedBpCode =
      String(req.user?.user_type || "").toLowerCase() === "bp"
        ? req.user?.bp_code || bp_code || null
        : bp_code || null;

    /* ==================================================================
       RESOLVED VALUES

       Report and Adjustment:
       - Use submitted Supplier, Contract, Periods, and rows.

       Return:
       - Inherit Supplier, Contract, and Periods.
       - Copy approved processed Accrual rows.
    ================================================================== */

    let resolvedPeriods = [...submittedPeriods];

    let resolvedBpCode = nullIfEmpty(
      typeof submittedBpCode === "string"
        ? submittedBpCode.trim()
        : submittedBpCode,
    );

    let resolvedContractId = nullIfEmpty(
      typeof contract_id === "string" ? contract_id.trim() : contract_id,
    );

    let linkedReport = null;
    let detailRowsToStage = [];

    /* ==================================================================
       VALIDATE ADJUSTMENT LINKED REPORT
    ================================================================== */

    if (isAdjustment) {
      const { rows: linkedRows } = await query(
        `
        SELECT
          Report_Number AS report_number,
          Report_Type AS report_type,
          FileName AS filename,
          Period AS period,
          BP_Code AS bp_code,
          Contract_ID AS contract_id,
          Status AS status
        FROM dbo.Report_Number
        WHERE Report_Number = @p1;
        `,
        [linkedReportNumber],
      );

      if (!linkedRows.length) {
        return res.status(404).json({
          error: `Linked report #${linkedReportNumber} was not found`,
        });
      }

      linkedReport = linkedRows[0];
    }

    /* ==================================================================
       LOAD RETURN SOURCE ACCRUAL
    ================================================================== */

    if (isReturn) {
      /*
       * Load and validate the linked Accrual header.
       */
      const { rows: linkedRows } = await query(
        `
        SELECT
          Report_Number AS report_number,
          Report_Type AS report_type,
          FileName AS filename,
          Period AS period,
          BP_Code AS bp_code,
          Contract_ID AS contract_id,
          Status AS status
        FROM dbo.Report_Number
        WHERE Report_Number = @p1;
        `,
        [linkedReportNumber],
      );

      if (!linkedRows.length) {
        return res.status(404).json({
          error:
            `Linked Accrual report #${linkedReportNumber} ` + "was not found",
        });
      }

      linkedReport = linkedRows[0];

      const linkedReportType = String(linkedReport.report_type || "")
        .trim()
        .toLowerCase();

      if (linkedReportType !== "accrual") {
        return res.status(400).json({
          error:
            `Report #${linkedReportNumber} is report type ` +
            `"${linkedReport.report_type || "Unknown"}". ` +
            "A Return must be linked to an Accrual report.",
        });
      }

      /*
       * A Return can be created only after the source Accrual
       * has been approved.
       */
      const linkedReportStatus = String(linkedReport.status || "")
        .trim()
        .toLowerCase();

      if (linkedReportStatus !== "approved") {
        return res.status(400).json({
          error:
            `Linked Accrual report #${linkedReportNumber} has status ` +
            `"${linkedReport.status || "Unknown"}". ` +
            "The Accrual must be approved before a Return can be created.",
        });
      }

      /*
       * Return inherits Supplier and Contract from the Accrual.
       */
      resolvedBpCode = nullIfEmpty(linkedReport.bp_code);
      resolvedContractId = nullIfEmpty(linkedReport.contract_id);

      /*
       * Load normalized periods from Report_Period.
       */
      const { rows: linkedPeriodRows } = await query(
        `
        SELECT DISTINCT
          Period AS period
        FROM dbo.Report_Period
        WHERE Report_Number = @p1
          AND Period IS NOT NULL
          AND LTRIM(
                RTRIM(
                  CAST(Period AS NVARCHAR(50))
                )
              ) <> ''
        ORDER BY Period;
        `,
        [linkedReportNumber],
      );

      resolvedPeriods = linkedPeriodRows
        .map((item) => String(item.period || "").trim())
        .filter(Boolean);

      /*
       * Fallback for older reports that store only
       * Report_Number.Period.
       */
      if (resolvedPeriods.length === 0 && linkedReport.period) {
        resolvedPeriods = String(linkedReport.period)
          .split(",")
          .map((value) => value.trim())
          .filter(Boolean);
      }

      resolvedPeriods = Array.from(new Set(resolvedPeriods)).sort(
        (left, right) => left.localeCompare(right),
      );

      if (resolvedPeriods.length === 0) {
        return res.status(400).json({
          error:
            `Linked Accrual report #${linkedReportNumber} ` +
            "does not contain an accounting period.",
        });
      }

      /*
       * Copy approved processed rows from Cur_Invoice_Detail.
       *
       * Verified source columns:
       * - Description
       * - Purchase_Dollars_Calc
       * - CAF
       * - CAF_Dollars
       */
      const { rows: sourceRows } = await query(
        `
        SELECT
          Customer_ID AS customer_id,
          Member_Number AS member_number,
          Member_Name AS member_name,
          Member_Address AS member_address,
          Member_City AS member_city,
          Member_State AS member_state,
          Member_Zip AS member_zip,

          PO AS po,
          Invoice AS invoice,
          Invoice_Date AS invoice_date,

          Ship_To AS ship_to,
          Ship_To_Address AS ship_to_address,
          Ship_To_City AS ship_to_city,
          Ship_To_State AS ship_to_state,
          Ship_To_Zip AS ship_to_zip,

          Item AS item,
          Manufacturer AS manufacturer,
          Manufacturer_Part AS manufacturer_part,
          UM AS um,
          Description AS description,
          UNSPSC AS unspsc,
          Category AS category,
          SubCategory AS subcategory,

          Retail_Price AS retail_price,
          Contract_Price AS contract_price,
          Qty AS qty,

          Purchase_Dollars_Calc AS purchase_dollars,
          CAF AS caf,
          CAF_Dollars AS caf_dollars

        FROM dbo.Cur_Invoice_Detail
        WHERE Report_Number = @p1
          AND LOWER(
                LTRIM(
                  RTRIM(
                    COALESCE(DQ_Status, '')
                  )
                )
              ) = 'approved'
        ORDER BY Cur_Detail_ID;
        `,
        [linkedReportNumber],
      );

      if (!sourceRows.length) {
        return res.status(400).json({
          error:
            `Linked Accrual report #${linkedReportNumber} ` +
            "does not contain approved processed rows in " +
            "Cur_Invoice_Detail. The Accrual must be approved " +
            "before a Return can be created.",
        });
      }

      /*
       * Build Return staging rows.
       *
       * Reverse:
       * - Purchase_Dollars_Calc
       * - CAF_Dollars
       *
       * Keep unchanged:
       * - CAF rate
       * - Quantity
       * - Retail Price
       * - Contract Price
       * - Member, invoice, item, and shipping data
       */
      detailRowsToStage = sourceRows.map((sourceRow) => ({
        ...sourceRow,

        purchase_dollars: reverseAmount(sourceRow.purchase_dollars),

        caf_dollars: reverseAmount(sourceRow.caf_dollars),
      }));
    } else {
      /*
       * Report and Adjustment use rows entered through the UI.
       */
      detailRowsToStage = rows;
    }

    if (!Array.isArray(detailRowsToStage) || detailRowsToStage.length === 0) {
      return res.status(400).json({
        error: "No detail rows are available to create the report",
      });
    }

    /* ================================================================
   VERIFY ACCOUNTING PERIOD IS OPEN
================================================================ */

    try {
      await validateOpenPeriods(resolvedPeriods);
    } catch (periodError) {
      return res.status(periodError.statusCode || 400).json({
        error: periodError.message,
        code: periodError.code || "ACCOUNTING_PERIOD_VALIDATION_FAILED",
        periods: periodError.periods || [],
      });
    }
    /* ==================================================================
       PERIOD SUMMARY
    ================================================================== */

    const periodSummary = resolvedPeriods.join(", ");

    /* ==================================================================
       MANUAL FILE NAME
    ================================================================== */

    const manualFileName =
      report_type === "Report"
        ? "MANUAL_REPORT"
        : report_type === "Adjustment"
          ? "MANUAL_ADJUSTMENT"
          : "MANUAL_RETURN";

    /* ==================================================================
       REPORT NOTE
    ================================================================== */

    const finalNote = isReturn
      ? [
          String(note || "").trim(),
          `Automatically reversed from Accrual Report #${linkedReportNumber}`,
        ]
          .filter(Boolean)
          .join(" - ")
      : String(note || "").trim();

    /* ==================================================================
       CREATE REPORT_NUMBER HEADER
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
        'submitted',
        @p10,
        GETUTCDATE(),
        GETUTCDATE()
      );
    `;

    const { rows: reportRows } = await query(reportInsertSql, [
      manualFileName,
      report_type,
      uploadedBy,
      uploadedByName,
      uploadedByType,
      periodSummary,
      resolvedBpCode,
      resolvedContractId,
      linkedReportNumber,
      finalNote,
    ]);

    const report = reportRows?.[0];

    const reportNumber = report?.report_number ?? report?.Report_Number ?? null;

    if (!reportNumber) {
      return res.status(500).json({
        error: "Failed to create report header: missing report number",
      });
    }

    /* ==================================================================
       STORE REPORT PERIODS
    ================================================================== */

    for (const selectedPeriod of resolvedPeriods) {
      await query(
        `
    INSERT INTO dbo.Report_Period
    (
      Report_Number,
      Period,
      Created_At_UTC
    )
    VALUES
    (
      @p1,
      @p2,
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
      [reportNumber, uploadedBy],
    );

    /* ==================================================================
       INSERT STAGING ROWS

       Verified Stg_Invoice_Raw columns:
       - Desc
       - Purchase_Dollars
       - CAF
       - CAF_Dollars

       Load_Batch_ID and Source_Hash are not inserted here and must
       remain nullable or have database defaults.
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

    for (const row of detailRowsToStage) {
      await query(stageSql, [
        reportNumber,

        nullIfEmpty(row.customer_id),
        nullIfEmpty(row.member_number),
        nullIfEmpty(row.member_name),
        nullIfEmpty(row.member_address),
        nullIfEmpty(row.member_city),
        nullIfEmpty(row.member_state),
        nullIfEmpty(row.member_zip),

        nullIfEmpty(row.po),
        nullIfEmpty(row.invoice),
        nullIfEmpty(row.invoice_date),

        nullIfEmpty(row.ship_to),
        nullIfEmpty(row.ship_to_address),
        nullIfEmpty(row.ship_to_city),
        nullIfEmpty(row.ship_to_state),
        nullIfEmpty(row.ship_to_zip),

        nullIfEmpty(row.item),
        nullIfEmpty(row.manufacturer),
        nullIfEmpty(row.manufacturer_part),
        nullIfEmpty(row.um),

        nullIfEmpty(row.desc ?? row.description),

        nullIfEmpty(row.unspsc),
        nullIfEmpty(row.category),
        nullIfEmpty(row.subcategory),

        nullableNumber(row.retail_price),
        nullableNumber(row.contract_price),
        nullableNumber(row.qty),

        nullableNumber(row.purchase_dollars ?? row.purchase_dollars_calc),

        nullableNumber(row.caf),
        nullableNumber(row.caf_dollars),
      ]);
    }

    /* ==================================================================
       AUDIT LOG

       Audit failure does not fail report creation.
    ================================================================== */

    try {
      const auditAction = isReturn
        ? "manual_create_return"
        : isAdjustment
          ? "manual_create_adjustment"
          : "manual_create_report";

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
          @p2,
          @p3,
          GETUTCDATE()
        );
        `,
        [
          uploadedBy,
          auditAction,

          JSON.stringify({
            report_number: reportNumber,
            report_type,
            filename: manualFileName,

            period: periodSummary,
            periods: resolvedPeriods,

            bp_code: resolvedBpCode,
            contract_id: resolvedContractId,

            related_report_number: linkedReportNumber,

            source_report_type: linkedReport?.report_type || null,

            source_row_count: isReturn ? detailRowsToStage.length : null,

            row_count: detailRowsToStage.length,

            reversed_fields: isReturn
              ? ["purchase_dollars_calc", "caf_dollars"]
              : [],

            validation_warnings: isReturn ? [] : validation_warnings,

            validation_error_details: isReturn ? "" : validation_error_details,

            processing_method: "scheduled_iics_workflow",
          }),
        ],
      );
    } catch (auditError) {
      console.warn("Manual report audit log skipped:", auditError.message);
    }

    /* ==================================================================
       RESPONSE
    ================================================================== */

    const message = isReturn
      ? `Return report #${reportNumber} was created from Accrual Report #${linkedReportNumber}. ${detailRowsToStage.length} approved processed row(s) were copied and reversed. The report is ready for scheduled Informatica processing.`
      : `${report_type} report #${reportNumber} was created and staged for scheduled Informatica processing.`;

    return res.json({
      ok: true,

      report_number: reportNumber,

      report: {
        ...report,

        period: periodSummary,
        periods: resolvedPeriods,

        bp_code: resolvedBpCode,
        contract_id: resolvedContractId,

        related_report_number: linkedReportNumber,
      },

      source_report: isReturn
        ? {
            report_number: linkedReport.report_number,

            report_type: linkedReport.report_type,

            status: linkedReport.status,

            row_count: detailRowsToStage.length,
          }
        : null,

      row_count: detailRowsToStage.length,

      status: "submitted",

      processing_method: "scheduled_iics_workflow",

      message,
    });
  } catch (error) {
    console.error("❌ POST /reports/manual-create error:", error);

    next(error);
  }
});

/* ======================================================================
   ACCOUNTING PERIOD STATUS
====================================================================== */

/* ======================================================================
   ACCOUNTING PERIOD STATUS
====================================================================== */

/* ======================================================================
   ACCOUNTING PERIOD MANAGEMENT

   Permissions:
   - Authenticated internal users can view periods
   - Authenticated internal users can create periods
   - Authenticated internal users can lock periods
   - Authenticated internal users can unlock periods

   Table:
   dbo.Accounting_Period

   Columns:
   - Accounting_Period_ID
   - Period
   - Is_Locked
   - Locked_By
   - Locked_At_UTC
   - Unlocked_By
   - Unlocked_At_UTC
   - Created_At_UTC
   - Updated_At_UTC
====================================================================== */

/* ======================================================================
   GET /reports/accounting-periods
====================================================================== */

router.get(
  "/reports/accounting-periods",
  requireAuth,
  requireInternalAccountingPeriodAccess,
  async (_req, res, next) => {
    try {
      const { rows } = await query(`
        SELECT
          Accounting_Period_ID AS accounting_period_id,
          Period AS period,
          Is_Locked AS is_locked,
          Locked_By AS locked_by,
          Locked_At_UTC AS locked_at_utc,
          Unlocked_By AS unlocked_by,
          Unlocked_At_UTC AS unlocked_at_utc,
          Created_At_UTC AS created_at_utc,
          Updated_At_UTC AS updated_at_utc
        FROM dbo.Accounting_Period
        ORDER BY Period DESC;
      `);

      const periods = rows.map((row) => ({
        accounting_period_id: row.accounting_period_id,
        period: row.period,
        is_locked: Boolean(row.is_locked),
        status: Boolean(row.is_locked) ? "closed" : "open",
        locked_by: row.locked_by || null,
        locked_at_utc: row.locked_at_utc || null,
        unlocked_by: row.unlocked_by || null,
        unlocked_at_utc: row.unlocked_at_utc || null,
        created_at_utc: row.created_at_utc || null,
        updated_at_utc: row.updated_at_utc || null,
      }));

      return res.status(200).json({
        success: true,
        count: periods.length,
        periods,
      });
    } catch (error) {
      console.error("❌ GET /reports/accounting-periods error:", error);
      next(error);
    }
  },
);

/* ======================================================================
   POST /reports/accounting-periods
   Creates a new accounting period as Open
====================================================================== */

router.post(
  "/reports/accounting-periods",
  requireAuth,
  requireInternalAccountingPeriodAccess,
  async (req, res, next) => {
    try {
      const period = normalizeAccountingPeriod(req.body?.period);

      if (!period) {
        return res.status(400).json({
          success: false,
          code: "INVALID_ACCOUNTING_PERIOD",
          message: "Accounting period must use YYYY-MM format.",
        });
      }

      /*
       * Check whether the period already exists.
       */
      const { rows: existingRows } = await query(
        `
        SELECT
          Accounting_Period_ID AS accounting_period_id,
          Period AS period,
          Is_Locked AS is_locked
        FROM dbo.Accounting_Period
        WHERE Period = @p1;
        `,
        [period],
      );

      if (existingRows.length > 0) {
        return res.status(409).json({
          success: false,
          code: "ACCOUNTING_PERIOD_ALREADY_EXISTS",
          message: `Accounting period ${period} already exists.`,
          period: {
            accounting_period_id: existingRows[0].accounting_period_id,
            period: existingRows[0].period,
            is_locked: Boolean(existingRows[0].is_locked),
            status: Boolean(existingRows[0].is_locked) ? "closed" : "open",
          },
        });
      }

      /*
       * Create the period as Open.
       */
      const { rows: insertedRows } = await query(
        `
        INSERT INTO dbo.Accounting_Period
        (
          Period,
          Is_Locked,
          Locked_By,
          Locked_At_UTC,
          Unlocked_By,
          Unlocked_At_UTC,
          Created_At_UTC,
          Updated_At_UTC
        )
        OUTPUT
          INSERTED.Accounting_Period_ID AS accounting_period_id,
          INSERTED.Period AS period,
          INSERTED.Is_Locked AS is_locked,
          INSERTED.Locked_By AS locked_by,
          INSERTED.Locked_At_UTC AS locked_at_utc,
          INSERTED.Unlocked_By AS unlocked_by,
          INSERTED.Unlocked_At_UTC AS unlocked_at_utc,
          INSERTED.Created_At_UTC AS created_at_utc,
          INSERTED.Updated_At_UTC AS updated_at_utc
        VALUES
        (
          @p1,
          0,
          NULL,
          NULL,
          NULL,
          NULL,
          GETUTCDATE(),
          GETUTCDATE()
        );
        `,
        [period],
      );

      const row = insertedRows[0];

      /*
       * Audit failure should not fail period creation.
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
            'create_accounting_period',
            @p2,
            GETUTCDATE()
          );
          `,
          [
            getCurrentUserIdentifier(req),
            JSON.stringify({
              period,
              status: "open",
            }),
          ],
        );
      } catch (auditError) {
        console.warn(
          "Create accounting period audit log skipped:",
          auditError.message,
        );
      }

      return res.status(201).json({
        success: true,
        message: `Accounting period ${period} was created successfully.`,
        period: {
          accounting_period_id: row.accounting_period_id,
          period: row.period,
          is_locked: Boolean(row.is_locked),
          status: "open",
          locked_by: row.locked_by || null,
          locked_at_utc: row.locked_at_utc || null,
          unlocked_by: row.unlocked_by || null,
          unlocked_at_utc: row.unlocked_at_utc || null,
          created_at_utc: row.created_at_utc || null,
          updated_at_utc: row.updated_at_utc || null,
        },
      });
    } catch (error) {
      console.error("❌ POST /reports/accounting-periods error:", error);

      /*
       * SQL Server duplicate-key errors.
       *
       * This protects against two users creating the same month
       * at nearly the same time.
       */
      if (error?.number === 2601 || error?.number === 2627) {
        return res.status(409).json({
          success: false,
          code: "ACCOUNTING_PERIOD_ALREADY_EXISTS",
          message: "This accounting period already exists.",
        });
      }

      next(error);
    }
  },
);

/* ======================================================================
   PUT /reports/accounting-periods/:period/lock
====================================================================== */

router.put(
  "/reports/accounting-periods/:period/lock",
  requireAuth,
  requireInternalAccountingPeriodAccess,
  async (req, res, next) => {
    try {
      const period = normalizeAccountingPeriod(req.params?.period);
      const lockedBy = getCurrentUserIdentifier(req);

      if (!period) {
        return res.status(400).json({
          success: false,
          code: "INVALID_ACCOUNTING_PERIOD",
          message: "Accounting period must use YYYY-MM format.",
        });
      }

      /*
       * Update only when the period exists and is currently open.
       *
       * This condition makes the operation safe when two users
       * try to lock the same period at the same time.
       */
      const { rows: updatedRows } = await query(
        `
        UPDATE dbo.Accounting_Period
        SET
          Is_Locked = 1,
          Locked_By = @p2,
          Locked_At_UTC = GETUTCDATE(),
          Unlocked_By = NULL,
          Unlocked_At_UTC = NULL,
          Updated_At_UTC = GETUTCDATE()
        OUTPUT
          INSERTED.Accounting_Period_ID AS accounting_period_id,
          INSERTED.Period AS period,
          INSERTED.Is_Locked AS is_locked,
          INSERTED.Locked_By AS locked_by,
          INSERTED.Locked_At_UTC AS locked_at_utc,
          INSERTED.Unlocked_By AS unlocked_by,
          INSERTED.Unlocked_At_UTC AS unlocked_at_utc,
          INSERTED.Created_At_UTC AS created_at_utc,
          INSERTED.Updated_At_UTC AS updated_at_utc
        WHERE Period = @p1
          AND Is_Locked = 0;
        `,
        [period, lockedBy],
      );

      if (updatedRows.length === 0) {
        const { rows: existingRows } = await query(
          `
          SELECT
            Accounting_Period_ID AS accounting_period_id,
            Period AS period,
            Is_Locked AS is_locked,
            Locked_By AS locked_by,
            Locked_At_UTC AS locked_at_utc
          FROM dbo.Accounting_Period
          WHERE Period = @p1;
          `,
          [period],
        );

        if (existingRows.length === 0) {
          return res.status(404).json({
            success: false,
            code: "ACCOUNTING_PERIOD_NOT_FOUND",
            message: `Accounting period ${period} is not configured.`,
          });
        }

        const existingPeriod = existingRows[0];

        return res.status(409).json({
          success: false,
          code: "ACCOUNTING_PERIOD_ALREADY_LOCKED",
          message: `Accounting period ${period} is already locked.`,
          period: {
            accounting_period_id: existingPeriod.accounting_period_id,
            period: existingPeriod.period,
            is_locked: true,
            status: "closed",
            locked_by: existingPeriod.locked_by || null,
            locked_at_utc: existingPeriod.locked_at_utc || null,
          },
        });
      }

      const row = updatedRows[0];

      /*
       * Audit failure should not fail the lock operation.
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
            'lock_accounting_period',
            @p2,
            GETUTCDATE()
          );
          `,
          [
            lockedBy,
            JSON.stringify({
              period,
              status: "closed",
              locked_by: lockedBy,
            }),
          ],
        );
      } catch (auditError) {
        console.warn(
          "Lock accounting period audit log skipped:",
          auditError.message,
        );
      }

      return res.status(200).json({
        success: true,
        message: `Accounting period ${period} was locked successfully.`,
        period: {
          accounting_period_id: row.accounting_period_id,
          period: row.period,
          is_locked: true,
          status: "closed",
          locked_by: row.locked_by || null,
          locked_at_utc: row.locked_at_utc || null,
          unlocked_by: row.unlocked_by || null,
          unlocked_at_utc: row.unlocked_at_utc || null,
          created_at_utc: row.created_at_utc || null,
          updated_at_utc: row.updated_at_utc || null,
        },
      });
    } catch (error) {
      console.error(
        `❌ PUT /reports/accounting-periods/${req.params?.period}/lock error:`,
        error,
      );

      next(error);
    }
  },
);

/* ======================================================================
   PUT /reports/accounting-periods/:period/unlock
====================================================================== */

router.put(
  "/reports/accounting-periods/:period/unlock",
  requireAuth,
  requireInternalAccountingPeriodAccess,
  async (req, res, next) => {
    try {
      const period = normalizeAccountingPeriod(req.params?.period);
      const unlockedBy = getCurrentUserIdentifier(req);

      if (!period) {
        return res.status(400).json({
          success: false,
          code: "INVALID_ACCOUNTING_PERIOD",
          message: "Accounting period must use YYYY-MM format.",
        });
      }

      /*
       * Update only when the period exists and is currently locked.
       */
      const { rows: updatedRows } = await query(
        `
        UPDATE dbo.Accounting_Period
        SET
          Is_Locked = 0,
          Unlocked_By = @p2,
          Unlocked_At_UTC = GETUTCDATE(),
          Updated_At_UTC = GETUTCDATE()
        OUTPUT
          INSERTED.Accounting_Period_ID AS accounting_period_id,
          INSERTED.Period AS period,
          INSERTED.Is_Locked AS is_locked,
          INSERTED.Locked_By AS locked_by,
          INSERTED.Locked_At_UTC AS locked_at_utc,
          INSERTED.Unlocked_By AS unlocked_by,
          INSERTED.Unlocked_At_UTC AS unlocked_at_utc,
          INSERTED.Created_At_UTC AS created_at_utc,
          INSERTED.Updated_At_UTC AS updated_at_utc
        WHERE Period = @p1
          AND Is_Locked = 1;
        `,
        [period, unlockedBy],
      );

      if (updatedRows.length === 0) {
        const { rows: existingRows } = await query(
          `
          SELECT
            Accounting_Period_ID AS accounting_period_id,
            Period AS period,
            Is_Locked AS is_locked,
            Unlocked_By AS unlocked_by,
            Unlocked_At_UTC AS unlocked_at_utc
          FROM dbo.Accounting_Period
          WHERE Period = @p1;
          `,
          [period],
        );

        if (existingRows.length === 0) {
          return res.status(404).json({
            success: false,
            code: "ACCOUNTING_PERIOD_NOT_FOUND",
            message: `Accounting period ${period} is not configured.`,
          });
        }

        const existingPeriod = existingRows[0];

        return res.status(409).json({
          success: false,
          code: "ACCOUNTING_PERIOD_ALREADY_OPEN",
          message: `Accounting period ${period} is already open.`,
          period: {
            accounting_period_id: existingPeriod.accounting_period_id,
            period: existingPeriod.period,
            is_locked: false,
            status: "open",
            unlocked_by: existingPeriod.unlocked_by || null,
            unlocked_at_utc: existingPeriod.unlocked_at_utc || null,
          },
        });
      }

      const row = updatedRows[0];

      /*
       * Audit failure should not fail the unlock operation.
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
            'unlock_accounting_period',
            @p2,
            GETUTCDATE()
          );
          `,
          [
            unlockedBy,
            JSON.stringify({
              period,
              status: "open",
              unlocked_by: unlockedBy,
            }),
          ],
        );
      } catch (auditError) {
        console.warn(
          "Unlock accounting period audit log skipped:",
          auditError.message,
        );
      }

      return res.status(200).json({
        success: true,
        message: `Accounting period ${period} was unlocked successfully.`,
        period: {
          accounting_period_id: row.accounting_period_id,
          period: row.period,
          is_locked: false,
          status: "open",
          locked_by: row.locked_by || null,
          locked_at_utc: row.locked_at_utc || null,
          unlocked_by: row.unlocked_by || null,
          unlocked_at_utc: row.unlocked_at_utc || null,
          created_at_utc: row.created_at_utc || null,
          updated_at_utc: row.updated_at_utc || null,
        },
      });
    } catch (error) {
      console.error(
        `❌ PUT /reports/accounting-periods/${req.params?.period}/unlock error:`,
        error,
      );

      next(error);
    }
  },
);

export default router;
